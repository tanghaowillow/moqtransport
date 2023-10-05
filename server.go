package moqtransport

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type PeerHandlerFunc func(*Peer)

func (h PeerHandlerFunc) Handle(p *Peer) {
	h(p)
}

type PeerHandler interface {
	Handle(*Peer)
}

type Server struct {
	Handler PeerHandler
}

type Listener interface {
	Accept(context.Context) (connection, error)
}

type quicListener struct {
	ql *quic.Listener
}

func (l *quicListener) Accept(ctx context.Context) (connection, error) {
	c, err := l.ql.Accept(ctx)
	if err != nil {
		return nil, err
	}
	qc := &quicConn{
		conn: c,
	}
	return qc, nil
}

type wtListener struct {
	ch chan *webtransport.Session
}

func (l *wtListener) Accept(ctx context.Context) (connection, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s := <-l.ch:
		wc := &WebTransportConn{
			sess: s,
		}
		return wc, nil
	}
}

func (s *Server) ListenWebTransport(ctx context.Context) error {
	ws := &webtransport.Server{
		H3: http3.Server{
			Addr:      ":4443",
			Port:      0,
			TLSConfig: &tls.Config{},
			QuicConfig: &quic.Config{
				GetConfigForClient:               nil,
				Versions:                         nil,
				HandshakeIdleTimeout:             0,
				MaxIdleTimeout:                   1<<63 - 1,
				RequireAddressValidation:         nil,
				MaxRetryTokenAge:                 0,
				MaxTokenAge:                      0,
				TokenStore:                       nil,
				InitialStreamReceiveWindow:       0,
				MaxStreamReceiveWindow:           0,
				InitialConnectionReceiveWindow:   0,
				MaxConnectionReceiveWindow:       0,
				AllowConnectionWindowIncrease:    nil,
				MaxIncomingStreams:               0,
				MaxIncomingUniStreams:            0,
				KeepAlivePeriod:                  0,
				DisablePathMTUDiscovery:          false,
				DisableVersionNegotiationPackets: false,
				Allow0RTT:                        false,
				EnableDatagrams:                  false,
				Tracer:                           nil,
			},
			Handler:            nil,
			EnableDatagrams:    false,
			MaxHeaderBytes:     0,
			AdditionalSettings: map[uint64]uint64{},
			StreamHijacker:     nil,
			UniStreamHijacker:  nil,
		},
		StreamReorderingTimeout: 0,
		CheckOrigin:             nil,
	}
	l := &wtListener{
		ch: make(chan *webtransport.Session),
	}
	http.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading failed: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case l.ch <- conn:
		}
		// Wait for end of request or session termination
		select {
		case <-r.Context().Done():
		case <-conn.Context().Done():
		}
	})
	// TODO: Implement graaceful server shutdown
	errCh := make(chan error)
	go func() {
		if err := ws.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()
	go func() {
		if err := s.Listen(ctx, l); err != nil {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	return nil
}

func (s *Server) ListenQUIC(ctx context.Context) error {
	listener, err := quic.ListenAddr("127.0.0.1:1909", generateTLSConfig(), &quic.Config{
		GetConfigForClient:               nil,
		Versions:                         nil,
		HandshakeIdleTimeout:             0,
		MaxIdleTimeout:                   1<<63 - 1,
		RequireAddressValidation:         nil,
		MaxRetryTokenAge:                 0,
		MaxTokenAge:                      0,
		TokenStore:                       nil,
		InitialStreamReceiveWindow:       0,
		MaxStreamReceiveWindow:           0,
		InitialConnectionReceiveWindow:   0,
		MaxConnectionReceiveWindow:       0,
		AllowConnectionWindowIncrease:    nil,
		MaxIncomingStreams:               0,
		MaxIncomingUniStreams:            0,
		KeepAlivePeriod:                  0,
		DisablePathMTUDiscovery:          false,
		DisableVersionNegotiationPackets: false,
		Allow0RTT:                        false,
		EnableDatagrams:                  true,
		Tracer:                           nil,
	})
	if err != nil {
		return err
	}
	l := &quicListener{
		ql: listener,
	}
	return s.Listen(ctx, l)
}

func (s *Server) Listen(ctx context.Context, listener Listener) error {
	for {
		conn, err := listener.Accept(context.TODO())
		if err != nil {
			return err
		}
		peer, err := newServerPeer(ctx, conn)
		if err != nil {
			log.Printf("failed to create new server peer: %v", err)
			switch {
			case errors.Is(err, errUnsupportedVersion):
				conn.CloseWithError(SessionTerminatedErrorCode, err.Error())
			case errors.Is(err, errMissingRoleParameter):
				conn.CloseWithError(SessionTerminatedErrorCode, err.Error())
			default:
				conn.CloseWithError(GenericErrorCode, "internal server error")
			}
			continue
		}
		// TODO: This should probably be a map keyed by the MoQ-URI the request
		// is targeting
		if s.Handler != nil {
			s.Handler.Handle(peer)
		}
		go func() {
			peer.run(ctx)
		}()
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"moq-00"},
	}
}
