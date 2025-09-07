package main

import (
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	FIXED_USERNAME = "ahmed"
	FIXED_PASSWORD = "ahmed"
	SSH_PORT       = "4443"
)

type Server struct {
	sshConfig     *ssh.ServerConfig
	tlsConfig     *tls.Config
	activeClients int32
	totalBytes    int64
	stopChan      chan struct{}
}

// ????? ????? TLS ?????
func generateTLSCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"VPN Tunnel"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"*"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ????? ???????
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
				atomic.AddInt32(&server.activeClients, 1)
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
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, // ???? ??? ???? ???????
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"ssh"},
	}

	return server, nil
}

// ??? ???????? ?? Buffer ???? (4MB)
func copyBuffer(dst io.Writer, src io.Reader, bufSize int) (int64, error) {
	buf := make([]byte, 4<<20)
	return io.CopyBuffer(dst, src, buf)
}

// ??????? ?? ?? ????
func (s *Server) handleClient(client net.Conn) {
	defer func() {
		client.Close()
		atomic.AddInt32(&s.activeClients, -1)
	}()

	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(client, s.sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" && newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "shell" || req.Type == "exec" || req.Type == "pty-req" {
					req.Reply(true, nil)
				} else {
					req.Reply(false, nil)
				}
			}
		}(requests)

		go func() {
			defer channel.Close()

			data := struct {
				HostToConnect string
				PortToConnect uint32
				OriginHost    string
				OriginPort    uint32
			}{}

			if err := ssh.Unmarshal(newChannel.ExtraData(), &data); err != nil {
				return
			}

			// ????? DNS
			if data.PortToConnect == 53 {
				data.HostToConnect = "1.1.1.1"
			}

			remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", data.HostToConnect, data.PortToConnect), 5*time.Second)
			if err != nil {
				if !strings.Contains(err.Error(), "actively refused") {
					log.Printf("Connect failed: %v", err)
				}
				return
			}
			defer remote.Close()

			if tcpConn, ok := remote.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			var once sync.Once
			closeFunc := func() {
				channel.Close()
				remote.Close()
			}

			go func() {
				n, _ := copyBuffer(channel, remote, 4<<20)
				atomic.AddInt64(&s.totalBytes, n)
				once.Do(closeFunc)
			}()

			n, _ := copyBuffer(remote, channel, 4<<20)
			atomic.AddInt64(&s.totalBytes, n)
			once.Do(closeFunc)
		}()
	}
}

// ????? ?????????? ?? 3 ?????
func (s *Server) printStats() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			activeClients := atomic.LoadInt32(&s.activeClients)
			if activeClients < 0 {
				activeClients = 0
			}
			totalBytes := atomic.LoadInt64(&s.totalBytes)
			megabytes := float64(totalBytes) / (1024 * 1024)

			fmt.Printf("\r\033[KTotal Data: %.3f MB | Active Clients: %d", megabytes, activeClients)
		}
	}
}

func main() {
	log.SetFlags(0)

	server, err := newServer()
	if err != nil {
		log.Fatal(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		close(server.stopChan)
		fmt.Println("\nShutting down...")
		os.Exit(0)
	}()

	listener, err := tls.Listen("tcp", ":"+SSH_PORT, server.tlsConfig)
	if err != nil {
		log.Fatal("Failed to start TLS listener:", err)
	}
	defer listener.Close()

	var localIP string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					localIP = ipnet.IP.String()
					break
				}
			}
		}
	}
	if localIP == "" {
		localIP = "0.0.0.0"
	}

	fmt.Println("=== VPN Tunnel Server Started ===")
	fmt.Printf("IP: %s\n", localIP)
	fmt.Printf("Port: %s\n", SSH_PORT)
	fmt.Printf("Username: %s\n", FIXED_USERNAME)
	fmt.Printf("Password: %s\n", FIXED_PASSWORD)
	fmt.Println("==============================")

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
