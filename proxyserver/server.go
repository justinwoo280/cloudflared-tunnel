package proxyserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pb "github.com/cloudflare/cloudflared/proxyserver/proto"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

// Config holds the proxy server configuration
type Config struct {
	UUID     string
	Port     string
	GRPCMode bool
}

// Server represents the proxy server
type Server struct {
	config Config
	log    *zerolog.Logger
	server *http.Server
	grpcS  *grpc.Server
}

// Nginx disguise page
const nginxHTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>`

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// NewConfig creates a new config from environment variables
func NewConfig() Config {
	return Config{
		UUID:     getEnv("UUID", "d342d11e-d424-4583-b36e-524ab1f0afa4"),
		Port:     getEnv("PORT", "8080"),
		GRPCMode: os.Getenv("MODE") == "grpc",
	}
}

// NewServer creates a new proxy server
func NewServer(config Config, log *zerolog.Logger) *Server {
	return &Server{
		config: config,
		log:    log,
	}
}

// Start starts the proxy server
func (s *Server) Start(ctx context.Context) error {
	s.log.Info().Str("uuid", s.config.UUID).Msg("Proxy server UUID configured")

	if s.config.GRPCMode {
		s.log.Info().Str("port", s.config.Port).Msg("Starting gRPC proxy server")
		return s.startGRPCServer(ctx)
	}

	s.log.Info().Str("port", s.config.Port).Msg("Starting WebSocket proxy server")
	return s.startWebSocketServer(ctx)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.grpcS != nil {
		s.grpcS.GracefulStop()
	}
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// ======================== gRPC Server ========================

type grpcProxyServer struct {
	pb.UnimplementedProxyServiceServer
	uuid string
	log  *zerolog.Logger
}

func (p *grpcProxyServer) Tunnel(stream pb.ProxyService_TunnelServer) error {
	// Get UUID from metadata for auth
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		p.log.Warn().Msg("gRPC: cannot get metadata")
		return nil
	}

	uuids := md.Get("uuid")
	if len(uuids) == 0 || uuids[0] != p.uuid {
		p.log.Warn().Msg("gRPC: UUID verification failed")
		return nil
	}

	p.log.Info().Msg("gRPC client connected")

	// Read first message to get target address
	firstMsg, err := stream.Recv()
	if err != nil {
		p.log.Err(err).Msg("gRPC: failed to read first packet")
		return err
	}

	data := firstMsg.GetContent()
	target, extraData := parseGRPCConnect(data)
	if target == "" {
		p.log.Warn().Msg("gRPC: invalid target address")
		stream.Send(&pb.SocketData{Content: []byte("ERROR:invalid target")})
		return nil
	}

	p.log.Info().Str("target", target).Msg("gRPC connecting")

	// Connect to target
	remote, err := net.Dial("tcp", target)
	if err != nil {
		p.log.Err(err).Msg("gRPC dial error")
		stream.Send(&pb.SocketData{Content: []byte("ERROR:" + err.Error())})
		return nil
	}
	defer remote.Close()

	p.log.Info().Str("target", target).Msg("gRPC connected")

	// Send connection success response
	if err := stream.Send(&pb.SocketData{Content: []byte("CONNECTED")}); err != nil {
		return err
	}

	// Send extra data
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// Bidirectional forwarding
	done := make(chan struct{}, 2)

	// gRPC -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if _, err := remote.Write(msg.GetContent()); err != nil {
				return
			}
		}
	}()

	// remote -> gRPC
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if err := stream.Send(&pb.SocketData{Content: buf[:n]}); err != nil {
				return
			}
		}
	}()

	<-done
	return nil
}

func parseGRPCConnect(data []byte) (target string, extraData []byte) {
	// Format: "CONNECT:host:port|extra_data"
	str := string(data)
	if !strings.HasPrefix(str, "CONNECT:") {
		return "", nil
	}

	str = strings.TrimPrefix(str, "CONNECT:")
	idx := strings.Index(str, "|")
	if idx < 0 {
		return str, nil
	}

	target = str[:idx]
	extraData = data[len("CONNECT:")+idx+1:]
	return target, extraData
}

func (s *Server) startGRPCServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", ":"+s.config.Port)
	if err != nil {
		return err
	}

	s.grpcS = grpc.NewServer()
	pb.RegisterProxyServiceServer(s.grpcS, &grpcProxyServer{
		uuid: s.config.UUID,
		log:  s.log,
	})

	go func() {
		<-ctx.Done()
		s.grpcS.GracefulStop()
	}()

	return s.grpcS.Serve(lis)
}

// ======================== WebSocket Server ========================

func (s *Server) startWebSocketServer(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/healthz", s.healthHandler)
	mux.HandleFunc("/", s.handler)

	s.server = &http.Server{
		Addr:    ":" + s.config.Port,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(shutdownCtx)
	}()

	err := s.server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	s.log.Debug().Str("method", r.Method).Str("path", r.URL.Path).Str("remote", r.RemoteAddr).Msg("Request received")

	// Check auth via header or path
	proto := r.Header.Get("Sec-WebSocket-Protocol")
	authorized := proto == s.config.UUID || strings.Contains(r.URL.Path, s.config.UUID)

	if !authorized || !websocket.IsWebSocketUpgrade(r) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(nginxHTML))
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, http.Header{"Sec-WebSocket-Protocol": {proto}})
	if err != nil {
		s.log.Err(err).Msg("WebSocket upgrade error")
		return
	}
	defer conn.Close()

	s.log.Info().Msg("WebSocket client connected")
	s.handleWebSocket(conn)
}

// WebSocket adapter for yamux
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

// handleWebSocket auto-detects client protocol: Yamux or simple text protocol
func (s *Server) handleWebSocket(conn *websocket.Conn) {
	// Read first frame to determine protocol type
	_, firstMsg, err := conn.ReadMessage()
	if err != nil {
		s.log.Err(err).Msg("Failed to read first message")
		return
	}

	// Yamux protocol magic number: 0x00 0x00 (version + type)
	// Simple protocol starts with "CONNECT:"
	if len(firstMsg) >= 2 && firstMsg[0] == 0x00 {
		s.log.Debug().Msg("Detected Yamux protocol")
		s.handleYamuxWithFirstFrame(conn, firstMsg)
	} else if strings.HasPrefix(string(firstMsg), "CONNECT:") {
		s.log.Debug().Msg("Detected simple protocol")
		s.handleSimpleProtocol(conn, firstMsg)
	} else {
		s.log.Warn().Bytes("first_bytes", firstMsg[:min(len(firstMsg), 16)]).Msg("Unknown protocol")
		return
	}
}

// handleSimpleProtocol handles simple text protocol (compatible with Cloudflare Workers)
func (s *Server) handleSimpleProtocol(conn *websocket.Conn, firstMsg []byte) {
	// Parse CONNECT:host:port|data
	msg := string(firstMsg)
	if !strings.HasPrefix(msg, "CONNECT:") {
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR:invalid message"))
		return
	}

	msg = strings.TrimPrefix(msg, "CONNECT:")
	idx := strings.Index(msg, "|")
	var target string
	var extraData []byte
	if idx >= 0 {
		target = msg[:idx]
		extraData = []byte(msg[idx+1:])
	} else {
		target = msg
	}

	s.log.Info().Str("target", target).Msg("Simple protocol connecting")

	// Connect to target
	remote, err := net.Dial("tcp", target)
	if err != nil {
		s.log.Err(err).Msg("Dial error")
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR:"+err.Error()))
		return
	}
	defer remote.Close()

	// Send connection success response
	if err := conn.WriteMessage(websocket.TextMessage, []byte("CONNECTED")); err != nil {
		return
	}

	s.log.Info().Str("target", target).Msg("Simple protocol connected")

	// Send extra data
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// Bidirectional forwarding
	done := make(chan struct{}, 2)

	// WebSocket -> remote
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			// Check control message
			if str := string(msg); str == "CLOSE" {
				return
			}
			if _, err := remote.Write(msg); err != nil {
				return
			}
		}
	}()

	// remote -> WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	<-done
	// Send close message
	conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
}

// handleYamuxWithFirstFrame handles Yamux protocol (with already read first frame)
func (s *Server) handleYamuxWithFirstFrame(conn *websocket.Conn, firstFrame []byte) {
	ws := &wsConnWithBuffer{
		Conn:           conn,
		firstFrame:     firstFrame,
		firstFrameRead: false,
	}

	// Create yamux server session
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.LogOutput = io.Discard

	session, err := yamux.Server(ws, cfg)
	if err != nil {
		s.log.Err(err).Msg("Yamux session error")
		return
	}
	defer session.Close()

	// Accept streams
	for {
		stream, err := session.Accept()
		if err != nil {
			if err != io.EOF {
				s.log.Debug().Err(err).Msg("Session closed")
			}
			return
		}
		go s.handleStream(stream)
	}
}

// wsConnWithBuffer is a WebSocket adapter with buffer (for replaying first frame)
type wsConnWithBuffer struct {
	*websocket.Conn
	firstFrame     []byte
	firstFrameRead bool
	reader         io.Reader
}

func (c *wsConnWithBuffer) Read(p []byte) (int, error) {
	// Return already read first frame first
	if !c.firstFrameRead && len(c.firstFrame) > 0 {
		c.firstFrameRead = true
		c.reader = bytes.NewReader(c.firstFrame)
	}

	for {
		if c.reader == nil {
			_, r, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			c.reader = r
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			continue
		}
		return n, err
	}
}

func (c *wsConnWithBuffer) Write(p []byte) (int, error) {
	err := c.WriteMessage(websocket.BinaryMessage, p)
	return len(p), err
}

func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	// First read: target address "host:port\n" (newline delimited)
	buf := make([]byte, 512)
	n, err := stream.Read(buf)
	if err != nil {
		return
	}

	data := buf[:n]

	// Find newline delimiter
	newlineIdx := -1
	for i, b := range data {
		if b == '\n' {
			newlineIdx = i
			break
		}
	}

	var target string
	var extraData []byte

	if newlineIdx >= 0 {
		target = string(data[:newlineIdx])
		if newlineIdx+1 < len(data) {
			extraData = data[newlineIdx+1:]
		}
	} else {
		// Fallback: no newline, treat entire data as target
		target = strings.TrimSpace(string(data))
	}

	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		s.log.Warn().Str("target", target).Msg("Invalid target")
		return
	}

	host, port := parts[0], parts[1]
	s.log.Info().Str("host", host).Str("port", port).Msg("Connecting to target")

	// Connect to target
	remote, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		s.log.Err(err).Msg("Dial error")
		return
	}
	defer remote.Close()

	s.log.Info().Str("host", host).Str("port", port).Msg("Connected to target")

	// Send extra data that came with target address (e.g., HTTP request)
	if len(extraData) > 0 {
		remote.Write(extraData)
	}

	// Bidirectional copy
	done := make(chan struct{})
	go func() {
		io.Copy(remote, stream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, remote)
		done <- struct{}{}
	}()
	<-done
}
