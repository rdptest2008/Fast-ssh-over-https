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
	"runtime"
	"strings"
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
	BUFFER_SIZE         = 256 * 1024 // 256 KB
	DEFAULT_IDLE_PERIOD = 10 * time.Minute
	CLEANUP_INTERVAL    = 1 * time.Minute
	GC_INTERVAL         = 30 * time.Minute
	GOROUTINE_CHECK     = 10000
	LOG_FILENAME        = "server.log"
	LOG_MAX_SIZE_MB     = 100
	LOG_MAX_BACKUPS     = 5
	LOG_MAX_AGE_DAYS    = 30
)

type Client struct {
	conn     net.Conn
	lastSeen atomic.Value // time.Time stored atomically
}

func (c *Client) SetLastSeen(t time.Time) {
	c.lastSeen.Store(t)
}

func (c *Client) LastSeen() time.Time {
	v := c.lastSeen.Load()
	if v == nil {
		return time.Time{}
	}
	return v.(time.Time)
}

type Server struct {
	sshConfig     *ssh.ServerConfig
	tlsConfig     *tls.Config
	activeClients int32
	totalBytes    int64
	stopChan      chan struct{}
	clients       sync.Map // key: net.Conn, value: *Client
}

// توليد شهادة TLS بسيطة (self-signed)
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
		IPAddresses:           []net.IP{net.IPv4(0, 0, 0, 0), net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// إنشاء السيرفر
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
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		NextProtos:               []string{"ssh"},
	}

	return server, nil
}

// إعادة استخدام البفرات مع مسح قبل الإرجاع
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, BUFFER_SIZE)
	},
}

// نسخ البيانات باستخدام bufio و بافر 256KB مع تجميع atomic
func copyBufferOptimized(dst io.Writer, src io.Reader, server *Server, client *Client) error {
	buf := bufPool.Get().([]byte)
	// لا نعدل طول الشريحة — نستخدم كامل السعة للقراءة
	defer func() {
		// مسح البيانات الحساسة قبل إرجاع البوفر
		for i := range buf {
			buf[i] = 0
		}
		bufPool.Put(buf)
	}()

	reader := bufio.NewReaderSize(src, BUFFER_SIZE)
	writer := bufio.NewWriterSize(dst, BUFFER_SIZE)

	var localBytes int64
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			written, werr := writer.Write(buf[:n])
			if werr == nil {
				_ = writer.Flush()
			} else {
				return werr
			}
			localBytes += int64(written)
			client.SetLastSeen(time.Now())
			if localBytes >= 1024*1024 { // تحديث كل 1MB
				atomic.AddInt64(&server.totalBytes, localBytes)
				localBytes = 0
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			}
			if localBytes > 0 {
				atomic.AddInt64(&server.totalBytes, localBytes)
			}
			break
		}
	}
	return nil
}

// تسجيل العميل
func (s *Server) registerClient(c net.Conn) *Client {
	client := &Client{conn: c}
	client.SetLastSeen(time.Now())
	s.clients.Store(c, client)
	return client
}

// إزالة العميل
func (s *Server) unregisterClient(c net.Conn) {
	s.clients.Delete(c)
}

// تنظيف العملاء الغير نشطين بشكل دوري
func (s *Server) cleanupIdleClients(timeout time.Duration) {
	ticker := time.NewTicker(CLEANUP_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.clients.Range(func(key, value interface{}) bool {
				client := value.(*Client)
				if now.Sub(client.LastSeen()) > timeout {
					log.Printf("Cleaning idle client: %v (idle %v)", client.conn.RemoteAddr(), now.Sub(client.LastSeen()))
					client.conn.Close()
					s.unregisterClient(client.conn)
				}
				return true
			})
		}
	}
}

// مراقبة عدد goroutines
func (s *Server) monitorGoroutines(limit int) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			num := runtime.NumGoroutine()
			if num > limit {
				log.Printf("WARNING: High goroutine count: %d (possible leak)", num)
			}
		}
	}
}

// فرض GC دوري
func (s *Server) periodicGC(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			log.Println("Running forced GC...")
			runtime.GC()
		}
	}
}

// إغلاق كل العملاء بشكل Graceful
func (s *Server) shutdownGracefully() {
	log.Println("Graceful shutdown: closing all active clients...")
	s.clients.Range(func(key, value interface{}) bool {
		client := value.(*Client)
		_ = client.conn.Close()
		return true
	})
}

// فرض Idle timeout لكل اتصال (مستمر)
func (s *Server) enforceIdleTimeout(c net.Conn, timeout time.Duration) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				val, ok := s.clients.Load(c)
				if !ok {
					return
				}
				client := val.(*Client)
				if time.Since(client.LastSeen()) > timeout {
					log.Printf("Idle timeout reached for %v, closing", c.RemoteAddr())
					c.Close()
					s.unregisterClient(c)
					return
				}
			}
		}
	}()
}

// التعامل مع كل عميل
func (s *Server) handleClient(clientConn net.Conn) {
	// تسجيل العميل مبكرًا لكي نقدر نتعقب الـ idle حتى قبل المصادقة
	client := s.registerClient(clientConn)
	defer func() {
		clientConn.Close()
		atomic.AddInt32(&s.activeClients, -1)
		s.unregisterClient(clientConn)
	}()

	// ضبط خصائص TCP لتحسين الأداء
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetReadBuffer(BUFFER_SIZE)
		_ = tcpConn.SetWriteBuffer(BUFFER_SIZE)
	}

	// تشغيل مراقب Idle خاص بكل اتصال
	s.enforceIdleTimeout(clientConn, DEFAULT_IDLE_PERIOD)

	sshConn, chans, reqs, err := ssh.NewServerConn(clientConn, s.sshConfig)
	if err != nil {
		// خطأ في الـ SSH handshake أو المصادقة
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel == nil {
			continue
		}
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
				if req == nil {
					continue
				}
				if req.Type == "shell" || req.Type == "exec" || req.Type == "pty-req" {
					_ = req.Reply(true, nil)
				} else {
					_ = req.Reply(false, nil)
				}
			}
		}(requests)

		// نلتقط نسخة محلية من newChannel لأن المتغير يتغير في الـ loop
		localChannel := newChannel
		go func(ch ssh.Channel, nc ssh.NewChannel) {
			defer ch.Close()

			data := struct {
				HostToConnect string
				PortToConnect uint32
				OriginHost    string
				OriginPort    uint32
			}{}

			if err := ssh.Unmarshal(nc.ExtraData(), &data); err != nil {
				return
			}

			// توجيه DNS (مثال: إذا كان المنفذ 53 نوجهه لسيرفر DNS محدد)
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
				_ = tcpConn.SetNoDelay(true)
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
				_ = tcpConn.SetReadBuffer(BUFFER_SIZE)
				_ = tcpConn.SetWriteBuffer(BUFFER_SIZE)
			}

			var once sync.Once
			closeFunc := func() {
				_ = ch.Close()
				_ = remote.Close()
			}

			// نسخ مزدوج باتجاهين
			go func() {
				_ = copyBufferOptimized(ch, remote, s, client)
				once.Do(closeFunc)
			}()

			_ = copyBufferOptimized(remote, ch, s, client)
			once.Do(closeFunc)
		}(channel, localChannel)
	}
}

// عرض الإحصائيات (runtime)
func (s *Server) printStats() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			activeClients := atomic.LoadInt32(&s.activeClients)
			if activeClients < 0 {
				activeClients = 0
			}
			totalBytes := atomic.LoadInt64(&s.totalBytes)
			megabytes := float64(totalBytes) / (1024 * 1024)

			fmt.Printf(
				"\r\033[KTotal Data: %.3f MB | Active Clients: %d | Goroutines: %d | Heap: %.2f MB",
				megabytes,
				activeClients,
				runtime.NumGoroutine(),
				float64(m.HeapAlloc)/(1024*1024),
			)
		}
	}
}

func main() {
	// إعدادات Log rotation باستخدام lumberjack
	log.SetOutput(&lumberjack.Logger{
		Filename:   LOG_FILENAME,
		MaxSize:    LOG_MAX_SIZE_MB, // megabytes
		MaxBackups: LOG_MAX_BACKUPS,
		MaxAge:     LOG_MAX_AGE_DAYS, // days
		Compress:   true,
	})
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	log.Println("Starting VPN Tunnel Server (production mode)...")

	server, err := newServer()
	if err != nil {
		log.Fatal(err)
	}

	// التقاط إشارات النظام لإيقاف Graceful
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Signal received, shutting down...")
		close(server.stopChan)
		server.shutdownGracefully()
		// ننتظر لحظات قصيرة لتمكين الإغلاق النظيف
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	listener, err := tls.Listen("tcp", ":"+SSH_PORT, server.tlsConfig)
	if err != nil {
		log.Fatal("Failed to start TLS listener:", err)
	}
	defer listener.Close()

	// احصل على IP محلي للعرض
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

	// شغّل مهام الصيانة الدورية
	go server.printStats()
	go server.cleanupIdleClients(DEFAULT_IDLE_PERIOD)
	go server.periodicGC(GC_INTERVAL)
	go server.monitorGoroutines(GOROUTINE_CHECK)

	// حلقة قبول الاتصالات
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-server.stopChan:
				return
			default:
				// تسجيل الخطأ ولكن نستمر بالعمل
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go server.handleClient(conn)
	}
}
