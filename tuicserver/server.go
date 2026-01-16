package tuicserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ZYKJShadow/tuic-protocol-go/address"
	"github.com/ZYKJShadow/tuic-protocol-go/auth"
	"github.com/ZYKJShadow/tuic-protocol-go/fragment"
	"github.com/ZYKJShadow/tuic-protocol-go/options"
	"github.com/ZYKJShadow/tuic-protocol-go/protocol"
	"github.com/ZYKJShadow/tuic-protocol-go/utils"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	ctx              context.Context
	cancel           context.CancelFunc
	listener         *quic.Listener
	authenticator    *Authenticate
	fragmentCacheMap map[quic.Connection]*fragment.FCache
	socketCacheMap   map[quic.Connection]*UdpSocket
	config           *Config
	log              *zerolog.Logger
	sync.RWMutex
}

func NewServer(cfg *Config, log *zerolog.Logger) (*Server, error) {
	certs, err := utils.LoadCerts(cfg.CertPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load certs")
		return nil, err
	}

	privateKey, err := utils.LoadPrivateKey(cfg.PrivateKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load private key")
		return nil, err
	}

	tlsConfig := &tls.Config{
		NextProtos:         cfg.ALPN,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS13,
		RootCAs:    x509.NewCertPool(),
	}

	if certs != nil && privateKey != nil {
		tlsConfig.Certificates = []tls.Certificate{
			{
				Certificate: certs,
				PrivateKey:  privateKey,
			},
		}
		tlsConfig.InsecureSkipVerify = false
	}

	quicConfig := &quic.Config{
		Versions:                       []quic.Version{quic.Version2},
		HandshakeIdleTimeout:           time.Duration(cfg.AuthTimeout) * time.Second,
		MaxIdleTimeout:                 time.Duration(cfg.MaxIdleTime) * time.Second,
		Allow0RTT:                      cfg.ZeroRTTHandshake,
		InitialStreamReceiveWindow:     8 * 1024 * 1024 * 2,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024 * 2,
		KeepAlivePeriod:                time.Second * 3,
		EnableDatagrams:                true,
		TokenStore:                     auth.NewAuthenticated(quic.NewLRUTokenStore(10, 4), make(chan string, 100), make(chan string, 100)),
	}

	conn, err := net.ListenPacket(protocol.NetworkUdp, cfg.Server)
	if err != nil {
		log.Error().Err(err).Msg("Failed to listen UDP")
		return nil, err
	}

	listener, err := quic.Listen(conn, tlsConfig, quicConfig)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create QUIC listener")
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	log.Info().Str("address", cfg.Server).Msg("TUIC server listening")

	return &Server{
		ctx:              ctx,
		cancel:           cancel,
		listener:         listener,
		config:           cfg,
		log:              log,
		authenticator:    NewAuthenticate(cfg.AuthTimeout),
		fragmentCacheMap: make(map[quic.Connection]*fragment.FCache),
		socketCacheMap:   make(map[quic.Connection]*UdpSocket),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		default:
			conn, err := s.listener.Accept(context.Background())
			if err != nil {
				if errors.Is(err, quic.ErrServerClosed) {
					return nil
				}
				s.log.Error().Err(err).Msg("Failed to accept connection")
				continue
			}

			s.log.Info().Str("remote", conn.RemoteAddr().String()).Msg("New TUIC connection")
			go s.onConnection(conn)
		}
	}
}

func (s *Server) Shutdown() error {
	s.cancel()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) onConnection(conn quic.Connection) {
	defer func() {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(0), "connection closed")
		s.cleanupConnection(conn)
	}()

	var g errgroup.Group

	g.Go(func() error {
		for {
			stream, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return err
			}
			g.Go(func() error {
				s.onHandleUniStream(conn, stream)
				return nil
			})
		}
	})

	g.Go(func() error {
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return err
			}
			g.Go(func() error {
				defer func() {
					_ = stream.Close()
					stream.CancelRead(protocol.NormalClosed)
					stream.CancelWrite(protocol.NormalClosed)
				}()
				s.onHandleStream(conn, stream)
				return nil
			})
		}
	})

	g.Go(func() error {
		for {
			datagram, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				return err
			}
			g.Go(func() error {
				s.onHandleDatagram(conn, datagram)
				return nil
			})
		}
	})

	err := g.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Debug().Err(err).Msg("Connection handler finished")
	}
}

func (s *Server) cleanupConnection(conn quic.Connection) {
	s.Lock()
	defer s.Unlock()

	if cache, ok := s.fragmentCacheMap[conn]; ok {
		_ = cache
		delete(s.fragmentCacheMap, conn)
	}

	if socket, ok := s.socketCacheMap[conn]; ok {
		socket.Close()
		delete(s.socketCacheMap, conn)
	}

	s.authenticator.RemoveConn(conn)
}

func (s *Server) onHandleDatagram(conn quic.Connection, datagram []byte) {
	reader := bytes.NewReader(datagram)

	var cmd protocol.Command
	err := cmd.Unmarshal(reader)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to read command from datagram")
		return
	}

	switch cmd.Type {
	case protocol.CmdAuthenticate, protocol.CmdConnect, protocol.CmdDissociate:
		s.log.Warn().Msg("Bad command in datagram")
	case protocol.CmdHeartbeat:
		// Heartbeat, do nothing
	case protocol.CmdPacket:
		err = s.packet(conn, reader, cmd.Options.(*options.PacketOptions), protocol.UdpRelayModeNative)
	default:
		s.log.Warn().Msg("Unknown command in datagram")
	}

	if err != nil {
		s.log.Error().Err(err).Msg("Failed to handle datagram")
	}
}

func (s *Server) onHandleUniStream(conn quic.Connection, stream quic.ReceiveStream) {
	var cmd protocol.Command
	err := cmd.Unmarshal(stream)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to read command from uni stream")
		return
	}

	if cmd.Type == protocol.CmdAuthenticate {
		err = s.authenticate(conn, cmd.Options.(*options.AuthenticateOptions))
		if err != nil {
			s.log.Error().Err(err).Msg("Authentication failed")
		}
		return
	}

	if !s.authenticator.GetAuth(conn) {
		err = s.authenticator.WaitForAuth(conn)
		if err != nil {
			s.log.Error().Err(err).Msg("Failed to wait for auth")
			return
		}
	}

	switch cmd.Type {
	case protocol.CmdPacket:
		err = s.packet(conn, stream, cmd.Options.(*options.PacketOptions), protocol.UdpRelayModeQuic)
	case protocol.CmdDissociate:
		err = s.dissociate(conn, stream)
	}

	if err != nil {
		s.log.Error().Err(err).Msg("Failed to handle uni stream")
	}
}

func (s *Server) onHandleStream(conn quic.Connection, stream quic.Stream) {
	var cmd protocol.Command
	err := cmd.Unmarshal(stream)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to read command from stream")
		return
	}

	if !s.authenticator.GetAuth(conn) {
		err = s.authenticator.WaitForAuth(conn)
		if err != nil {
			s.log.Error().Err(err).Msg("Failed to wait for auth")
			return
		}
	}

	switch cmd.Type {
	case protocol.CmdAuthenticate:
		s.log.Warn().Msg("Bad authenticate command in bi stream")
	case protocol.CmdConnect:
		err = s.connect(stream, cmd.Options.(*options.ConnectOptions))
	case protocol.CmdPacket:
		s.log.Warn().Msg("Bad packet command in bi stream")
	case protocol.CmdDissociate:
		s.log.Warn().Msg("Bad dissociate command in bi stream")
	case protocol.CmdHeartbeat:
		s.log.Warn().Msg("Bad heartbeat command in bi stream")
	default:
		s.log.Warn().Msg("Unknown command type")
	}

	if err != nil && err != io.EOF && !strings.Contains(err.Error(), "i/o timeout") {
		var streamErr *quic.StreamError
		if errors.As(err, &streamErr) && streamErr.ErrorCode == protocol.NormalClosed {
			return
		}
		s.log.Error().Err(err).Msg("Failed to handle stream")
	}
}

func (s *Server) authenticate(conn quic.Connection, opts *options.AuthenticateOptions) error {
	tlsConn := conn.ConnectionState().TLS
	label := string(opts.UUID)

	token, err := tlsConn.ExportKeyingMaterial(label, []byte(s.config.Password), 32)
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to export keying material")
		return err
	}

	if !bytes.Equal(token, opts.Token) {
		s.log.Warn().Str("remote", conn.RemoteAddr().String()).Msg("Invalid token")
		return errors.New("invalid token")
	}

	s.authenticator.SetAuth(conn, true)
	s.log.Info().Str("remote", conn.RemoteAddr().String()).Msg("Client authenticated")

	return nil
}

func (s *Server) dissociate(conn quic.Connection, stream io.Reader) error {
	var opts options.DissociateOptions
	b := make([]byte, 2)
	_, err := io.ReadFull(stream, b)
	if err != nil {
		return err
	}

	err = opts.Unmarshal(b)
	if err != nil {
		return err
	}

	s.RLock()
	cache := s.fragmentCacheMap[conn]
	s.RUnlock()

	if cache != nil {
		cache.DelFragment(opts.AssocID)
	}

	s.RLock()
	udpSocket := s.socketCacheMap[conn]
	s.RUnlock()

	if udpSocket != nil {
		udpSocket.Del(opts.AssocID)
	}

	return nil
}

// TCP relay
func (s *Server) connect(stream quic.Stream, opts *options.ConnectOptions) error {
	conn, err := s.dialTCP(stream, opts.Addr)
	if err != nil {
		return err
	}

	_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(s.config.MaxIdleTime)))

	defer func() {
		_ = conn.Close()
	}()

	go func() {
		_ = s.relay(conn, stream)
	}()

	return s.relay(stream, conn)
}

func (s *Server) dialTCP(stream quic.Stream, addr address.Address) (net.Conn, error) {
	rc, err := net.DialTimeout(protocol.NetworkTcp, addr.String(), time.Second*time.Duration(s.config.MaxIdleTime))
	if err != nil {
		s.log.Error().Err(err).Str("addr", addr.String()).Msg("Failed to dial TCP")
		s.sendConnectError(stream, addr)
		return nil, err
	}

	s.sendConnectSuccess(stream, rc)
	s.log.Debug().Str("addr", addr.String()).Msg("TCP connection established")

	return rc, nil
}

func (s *Server) sendConnectError(stream quic.Stream, addr address.Address) {
	var reply []byte
	if addr.TypeCode() == address.AddrTypeDomain || addr.TypeCode() == address.AddrTypeIPv4 {
		reply = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	} else {
		reply = append([]byte{0x05, 0x04, 0x00, 0x04}, make([]byte, 18)...)
	}
	_, _ = stream.Write(reply)
}

func (s *Server) sendConnectSuccess(stream quic.Stream, conn net.Conn) {
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	var reply []byte

	if localAddr.IP.To4() != nil {
		reply = []byte{0x05, 0x00, 0x00, 0x01}
		reply = append(reply, localAddr.IP.To4()...)
	} else {
		reply = []byte{0x05, 0x00, 0x00, 0x04}
		reply = append(reply, localAddr.IP.To16()...)
	}

	port := uint16(localAddr.Port)
	reply = append(reply, byte(port>>8), byte(port&0xff))
	_, _ = stream.Write(reply)
}

func (s *Server) relay(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)

	for {
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			var e *quic.StreamError
			if errors.As(err, &e) && e.ErrorCode == protocol.NormalClosed {
				return nil
			}
			return err
		}

		if n > 0 {
			_, err = dst.Write(buf[:n])
			if err != nil {
				return err
			}
		}
	}
}

// UDP relay
func (s *Server) packet(conn quic.Connection, stream io.Reader, opts *options.PacketOptions, mode string) error {
	data := make([]byte, opts.Size)
	_, err := io.ReadFull(stream, data)
	if err != nil {
		return err
	}

	if opts.FragTotal > 1 {
		return s.handleFragmentedPacket(conn, data, mode, opts)
	}

	return s.udpRelay(conn, opts.AssocID, data, mode, opts.Addr)
}

func (s *Server) handleFragmentedPacket(conn quic.Connection, data []byte, mode string, opts *options.PacketOptions) error {
	s.Lock()
	cache, ok := s.fragmentCacheMap[conn]
	if !ok {
		cache = fragment.NewFCache()
		s.fragmentCacheMap[conn] = cache
	}
	s.Unlock()

	data = cache.AddFragment(opts.AssocID, opts.FragID, opts.FragTotal, opts.Size, data)
	if data != nil {
		return s.udpRelay(conn, opts.AssocID, data, mode, opts.Addr)
	}

	return nil
}

func (s *Server) udpRelay(conn quic.Connection, assocID uint16, data []byte, mode string, addr address.Address) error {
	s.Lock()
	udpSocket, ok := s.socketCacheMap[conn]
	if !ok {
		udpSocket = NewUdpSocket(mode)
		s.socketCacheMap[conn] = udpSocket
	}
	s.Unlock()

	udp := udpSocket.Get(assocID)
	if udp == nil {
		remoteAddr, err := net.ResolveUDPAddr(protocol.NetworkUdp, addr.String())
		if err != nil {
			return err
		}

		udp, err = net.DialUDP(protocol.NetworkUdp, nil, remoteAddr)
		if err != nil {
			return err
		}

		udpSocket.Set(assocID, udp)
		go s.readUDP(conn, udp, assocID, mode, addr)
	}

	_ = udp.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(s.config.MaxIdleTime)))
	_, err := udp.Write(data)
	return err
}

func (s *Server) readUDP(conn quic.Connection, udp *net.UDPConn, assocID uint16, mode string, remoteAddr address.Address) {
	data := make([]byte, s.config.MaxPacketSize)
	for {
		_ = udp.SetReadDeadline(time.Now().Add(time.Second * time.Duration(s.config.MaxIdleTime)))

		n, err := udp.Read(data)
		if err != nil {
			break
		}

		opts := &options.PacketOptions{
			AssocID:   assocID,
			FragTotal: 1,
			FragID:    0,
			Size:      uint16(n),
			Addr:      remoteAddr,
		}

		opts.CalFragTotal(data[:n], s.config.MaxPacketSize)

		if opts.FragTotal > 1 {
			s.sendFragmentedUDP(conn, data[:n], mode, opts)
		} else {
			s.sendUDP(conn, data[:n], mode, opts)
		}
	}
}

func (s *Server) sendFragmentedUDP(conn quic.Connection, data []byte, mode string, opts *options.PacketOptions) {
	fragSize := (len(data) + int(opts.FragTotal) - 1) / int(opts.FragTotal)
	opts.Size = uint16(fragSize)

	for i := 0; i < int(opts.FragTotal); i++ {
		opts.FragID = uint8(i)
		start := i * fragSize
		end := start + fragSize
		if end > len(data) {
			end = len(data)
		}
		s.sendUDP(conn, data[start:end], mode, opts)
	}
}

func (s *Server) sendUDP(conn quic.Connection, fragment []byte, mode string, opts *options.PacketOptions) {
	opts.Size = uint16(len(fragment))
	cmd := protocol.Command{
		Version: protocol.VersionMajor,
		Type:    protocol.CmdPacket,
		Options: opts,
	}

	cmdBytes, err := cmd.Marshal()
	if err != nil {
		s.log.Error().Err(err).Msg("Failed to marshal packet")
		return
	}

	cmdBytes = append(cmdBytes, fragment...)

	switch mode {
	case protocol.UdpRelayModeQuic:
		err = s.sendUniStream(conn, cmdBytes)
	case protocol.UdpRelayModeNative:
		err = conn.SendDatagram(cmdBytes)
	}

	if err != nil {
		s.log.Error().Err(err).Msg("Failed to send UDP packet")
	}
}

func (s *Server) sendUniStream(conn quic.Connection, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}

	defer func() {
		_ = stream.Close()
	}()

	_, err = stream.Write(data)
	return err
}
