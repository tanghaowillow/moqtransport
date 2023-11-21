package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"time"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/mengelbart/moqtransport"
)

type fragment struct {
	moof mp4.MoofBox
	mdat mp4.MdatBox
}

type segment struct {
	fragments []*fragment
}

type mediaTrack interface {
	GetSegment(context.Context) segment
	Done() <-chan struct{}
}

type source struct {
	tracks map[string]mediaTrack
}

type Server struct {
	// peers       map[*moqtransport.Peer]string
	// nextTrackID uint64

	streams map[string]*source

	lock sync.Mutex
	moq  *moqtransport.Server
}

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

func newServer() *Server {
	s := &Server{
		moq: &moqtransport.Server{
			Handler:   nil,
			TLSConfig: generateTLSConfig(),
		},
	}

	return s
}

func main() {
	s := newServer()
	s.moq.Handler = moqtransport.PeerHandlerFunc(func(p *moqtransport.Peer) {
		s.handle(p)
	})
	s.moq.ListenQUIC(context.Background(), "0:0:0:0:4433")

}

func (s *Server) handle(p *moqtransport.Peer) {
	p.OnSubscription(func(namespace, trackname string, track *moqtransport.SendTrack) (uint64, time.Duration, error) {
		// find the track by namespace/trackname

		s.lock.Lock()

		s.lock.Unlock()

		return 1, time.Duration(0), nil
	})
}
