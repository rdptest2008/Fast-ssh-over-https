package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	FIXED_USERNAME      = "ahmed"
	FIXED_PASSWORD      = "ahmed"
	SSH_PORT            = "4443"
	BUFFER_SIZE         = 512 * 1024 // 512 KB
	DEFAULT_IDLE_PERIOD = 10 * time.Minute
	LOG_FILENAME        = "server.log"
	LOG_MAX_SIZE_MB     = 100
	LOG_MAX_BACKUPS     = 5
	LOG_MAX_AGE_DAYS    = 30
)

type ClientStats struct {
	Conn      net.Conn
	BytesSent int64
	BytesRecv int64
	LastSeen  atomic.Value
	Connected time.Time
}

func (c *ClientStats) SetLastSeen(t time.Time) {
	c.LastSeen.Store(t)
}

func (c *ClientStats) LastSeenTime() time.Time {
	v := c.LastSeen.Load()
	if v == nil {
		return time.Time{}
	}
	return v.(time.Time)
}

type Server struct {
	sshConfig *ssh.ServerConfig
	tlsConfig *tls.Config
	stopChan  chan struct{}
	clients   sync.Map
	totalData int64
}

// توليد شهادة TLS
func generateTLSCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"VPN Tunnel"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func newServer() (*Server, error) {
	server := &Server{stopChan: make(chan struct{})}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %v", err)
	}

	server.sshConfig = &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == FIXED_USERNAME && string(pass) == FIXED_PASSWORD {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	server.sshConfig.AddHostKey(signer)

	cert, err := generateTLSCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %v", err)
	}
	server.tlsConfig = &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		NextProtos:               []string{"ssh"},
	}
	return server, nil
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, BUFFER_SIZE)
	},
}

func copyBuffer(dst io.Writer, src io.Reader, client *ClientStats, sent bool, server *Server) error {
	buf := bufPool.Get().([]byte)
	defer func() {
		for i := range buf {
			buf[i] = 0
		}
		bufPool.Put(buf)
	}()

	reader := bufio.NewReaderSize(src, BUFFER_SIZE)
	writer := bufio.NewWriterSize(dst, BUFFER_SIZE)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			written, werr := writer.Write(buf[:n])
			if werr == nil {
				_ = writer.Flush()
			} else {
				return werr
			}
			if sent {
				atomic.AddInt64(&client.BytesSent, int64(written))
			} else {
				atomic.AddInt64(&client.BytesRecv, int64(written))
			}
			atomic.AddInt64(&server.totalData, int64(written))
			client.SetLastSeen(time.Now())
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}
	return nil
}

func (s *Server) registerClient(c net.Conn) *ClientStats {
	client := &ClientStats{
		Conn:      c,
		Connected: time.Now(),
	}
	client.SetLastSeen(time.Now())
	s.clients.Store(c, client)
	return client
}

func (s *Server) unregisterClient(c net.Conn) {
	s.clients.Delete(c)
}

func (s *Server) enforceIdleTimeout(client *ClientStats, timeout time.Duration) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				if time.Since(client.LastSeenTime()) > timeout {
					client.Conn.Close()
					s.unregisterClient(client.Conn)
					return
				}
			}
		}
	}()
}

func handleDirectTCPIP(client *ClientStats, newChannel ssh.NewChannel, server *Server) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	data := struct {
		HostToConnect string
		PortToConnect uint32
		OriginHost    string
		OriginPort    uint32
	}{}

	if err := ssh.Unmarshal(newChannel.ExtraData(), &data); err != nil {
		return
	}

	remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", data.HostToConnect, data.PortToConnect), 5*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	var once sync.Once
	closeFunc := func() {
		channel.Close()
		remote.Close()
	}

	go func() {
		_ = copyBuffer(remote, channel, client, true, server)
		once.Do(closeFunc)
	}()
	_ = copyBuffer(channel, remote, client, false, server)
	once.Do(closeFunc)
}

func (s *Server) handleClient(conn net.Conn) {
	client := s.registerClient(conn)
	defer func() {
		conn.Close()
		s.unregisterClient(conn)
	}()

	s.enforceIdleTimeout(client, DEFAULT_IDLE_PERIOD)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel == nil {
			continue
		}
		if newChannel.ChannelType() == "direct-tcpip" {
			go handleDirectTCPIP(client, newChannel, s)
		} else {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(requests)
			go copyBuffer(channel, channel, client, true, s)
		}
	}
}

func (s *Server) printStats() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			fmt.Print("\033[H\033[2J") // clear terminal
			count := 0
			s.clients.Range(func(_, _ interface{}) bool {
				count++
				return true
			})
			totalMB := float64(atomic.LoadInt64(&s.totalData)) / 1024 / 1024
			fmt.Printf("Active Clients: %d | Total Data: %.2f MB\n", count, totalMB)
			s.clients.Range(func(_, value interface{}) bool {
				c := value.(*ClientStats)
				fmt.Printf("IP: %s | Sent: %.2f MB | Recv: %.2f MB | Last Active: %s | Connected: %s\n",
					c.Conn.RemoteAddr(),
					float64(c.BytesSent)/1024/1024,
					float64(c.BytesRecv)/1024/1024,
					time.Since(c.LastSeenTime()).Truncate(time.Second),
					time.Since(c.Connected).Truncate(time.Second),
				)
				return true
			})
		}
	}
}

func main() {
	log.SetOutput(&lumberjack.Logger{
		Filename:   LOG_FILENAME,
		MaxSize:    LOG_MAX_SIZE_MB,
		MaxBackups: LOG_MAX_BACKUPS,
		MaxAge:     LOG_MAX_AGE_DAYS,
		Compress:   true,
	})
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	server, err := newServer()
	if err != nil {
		log.Fatal(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		close(server.stopChan)
		server.clients.Range(func(_, value interface{}) bool {
			c := value.(*ClientStats)
			c.Conn.Close()
			return true
		})
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	listener, err := tls.Listen("tcp", ":"+SSH_PORT, server.tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("VPN Tunnel Server Started on port %s\n", SSH_PORT)
	go server.printStats()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-server.stopChan:
				return
			default:
				continue
			}
		}
		go server.handleClient(conn)
	}
}
