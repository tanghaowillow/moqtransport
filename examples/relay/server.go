package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"sync"

	"github.com/mengelbart/moqtransport"
	"github.com/mengelbart/moqtransport/quicmoq"
	"github.com/mengelbart/moqtransport/webtransportmoq"
	"github.com/mengelbart/qlog"
	"github.com/mengelbart/qlog/moqt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// RelayServer is a simple MOQ relay server that accepts MOQ publishes and subscribes
// and relays them to other MOQ clients.
type RelayServer struct {
	addr      string
	tlsConfig *tls.Config

	// Track announcements by namespace
	announcements    map[string][]string
	announcementLock sync.RWMutex

	// Track subscriptions by namespace and track
	subscriptions    map[string]map[string][]*relaySubscription
	subscriptionLock sync.RWMutex

	// Track publishers by namespace and track
	publishers    map[string]map[string]*relaySession
	publisherLock sync.RWMutex
}

// relaySubscription represents a client that has subscribed to a track
type relaySubscription struct {
	namespace  []string
	trackName  string
	subscriber moqtransport.Publisher
}

// NewRelayServer creates a new MOQ relay server
func NewRelayServer(addr string, tlsConfig *tls.Config) *RelayServer {
	return &RelayServer{
		addr:          addr,
		tlsConfig:     tlsConfig,
		announcements: make(map[string][]string),
		subscriptions: make(map[string]map[string][]*relaySubscription),
		publishers:    make(map[string]map[string]*relaySession),
	}
}

// Run starts the relay server
func (s *RelayServer) Run(ctx context.Context) error {
	// Set up QUIC listener
	listener, err := quic.ListenAddr(s.addr, s.tlsConfig, &quic.Config{
		EnableDatagrams: true,
	})
	if err != nil {
		return err
	}

	// Set up WebTransport server
	wt := webtransport.Server{
		H3: http3.Server{
			Addr:      s.addr,
			TLSConfig: s.tlsConfig,
		},
	}

	// Handle WebTransport connections
	http.HandleFunc("/moq", func(w http.ResponseWriter, r *http.Request) {
		session, err := wt.Upgrade(w, r)
		if err != nil {
			log.Printf("upgrading to webtransport failed: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.handleConnection(webtransportmoq.NewServer(session))
	})

	// Accept QUIC connections
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}

		// Check the negotiated protocol
		if conn.ConnectionState().TLS.NegotiatedProtocol == "h3" {
			// Handle WebTransport over HTTP/3
			go wt.ServeQUICConn(conn)
		} else if conn.ConnectionState().TLS.NegotiatedProtocol == "moq-00" {
			// Handle direct MOQ over QUIC
			go s.handleConnection(quicmoq.NewServer(conn))
		}
	}
}

// handleConnection processes a new MOQ connection
func (s *RelayServer) handleConnection(conn moqtransport.Connection) {
	// Create a new MOQ session
	session := moqtransport.NewSession(conn.Protocol(), conn.Perspective(), 100)

	// Set up the transport with our handler
	transport := &moqtransport.Transport{
		Conn:    conn,
		Handler: s.getHandler(session),
		Qlogger: qlog.NewQLOGHandler(nil, "MOQ Relay", "MOQ Relay", conn.Perspective().String(), moqt.Schema),
		Session: session,
	}

	// Run the transport
	if err := transport.Run(); err != nil {
		log.Printf("MOQ Session initialization failed: %v", err)
		conn.CloseWithError(0, "session initialization error")
		return
	}
}

// getHandler returns a handler for MOQ messages
func (s *RelayServer) getHandler(session *moqtransport.Session) moqtransport.Handler {
	return moqtransport.HandlerFunc(func(w moqtransport.ResponseWriter, r *moqtransport.Message) {
		switch r.Method {
		case moqtransport.MessageAnnounce:
			s.handleAnnounce(w, r, session)
		case moqtransport.MessageSubscribe:
			s.handleSubscribe(w, r, session)
		case moqtransport.MessageUnannounce:
			s.handleUnannounce(w, r)
		case moqtransport.MessageSubscribeAnnounces:
			s.handleSubscribeAnnounces(w, r)
		case moqtransport.MessageTrackStatusRequest:
			s.handleTrackStatusRequest(w, r)
		}
	})
}

// handleAnnounce processes an announcement from a client
func (s *RelayServer) handleAnnounce(w moqtransport.ResponseWriter, r *moqtransport.Message, session *moqtransport.Session) {
	namespaceKey := namespaceToKey(r.Namespace)

	// Register the publisher
	s.publisherLock.Lock()
	defer s.publisherLock.Unlock()

	// Create maps if they don't exist
	if _, ok := s.publishers[namespaceKey]; !ok {
		s.publishers[namespaceKey] = make(map[string]*relaySession)
	}

	// // Check if we already have a publisher for this track
	// if _, ok := s.publishers[namespaceKey][r.Track]; ok {
	// 	log.Printf("track already exists: %v", r.Track)
	// 	w.Reject(moqtransport.ErrorCodeAnnouncementUninterested, "track already exists")
	// 	return
	// }

	// // Add the publisher
	// s.publishers[namespaceKey][r.Track] = &relaySession{

	// 	namespace: r.Namespace,
	// 	trackName: r.Track,
	// 	session:   session,
	// }

	// Accept the announcement
	if err := w.Accept(); err != nil {
		log.Printf("Failed to accept announcement: %v", err)
		return
	}

	// Store the announcement
	s.announcementLock.Lock()
	s.announcements[namespaceKey] = r.Namespace
	s.announcementLock.Unlock()

	log.Printf("Accepted announcement for namespace: %v", r.Namespace)
}

// subscribe subscribes to a track and setup a relay session
func (s *RelayServer) subscribe(namespace []string, trackName string, publisher moqtransport.Publisher) error {

}

// handleSubscribe processes a subscription request from a client
func (s *RelayServer) handleSubscribe(w moqtransport.ResponseWriter, r *moqtransport.Message, session *moqtransport.Session) {
	namespaceKey := namespaceToKey(r.Namespace)

	// Check if we have publishers for this namespace
	s.publisherLock.RLock()
	_, nsExists := s.publishers[namespaceKey]
	s.publisherLock.RUnlock()

	if !nsExists {
		// No publishers for this namespace
		w.Reject(moqtransport.ErrorCodeSubscribeTrackDoesNotExist, "no publishers for this namespace")
		return
	}

	// Accept the subscription
	if err := w.Accept(); err != nil {
		log.Printf("Failed to accept subscription: %v", err)
		return
	}

	// Get the publisher interface
	publisher, ok := w.(moqtransport.Publisher)
	if !ok {
		log.Printf("Subscription response writer does not implement publisher")
		return
	}

	// Create a relay subscription
	sub := &relaySubscription{
		namespace:  r.Namespace,
		trackName:  r.Track,
		subscriber: publisher,
	}

	// Register the subscription
	s.subscriptionLock.Lock()
	defer s.subscriptionLock.Unlock()

	// Create maps if they don't exist
	if _, ok := s.subscriptions[namespaceKey]; !ok {
		s.subscriptions[namespaceKey] = make(map[string][]*relaySubscription)
	}

	// Add the subscription
	s.subscriptions[namespaceKey][r.Track] = append(s.subscriptions[namespaceKey][r.Track], sub)

	log.Printf("Accepted subscription for namespace: %v, track: %s", r.Namespace, r.Track)
}

// handleUnannounce processes an unannouncement from a client
func (s *RelayServer) handleUnannounce(w moqtransport.ResponseWriter, r *moqtransport.Message) {
	namespaceKey := namespaceToKey(r.Namespace)

	// Remove the announcement
	s.announcementLock.Lock()
	delete(s.announcements, namespaceKey)
	s.announcementLock.Unlock()

	// Remove all publishers for this namespace
	s.publisherLock.Lock()
	delete(s.publishers, namespaceKey)
	s.publisherLock.Unlock()

	log.Printf("Processed unannouncement for namespace: %v", r.Namespace)
}

// handleSubscribeAnnounces processes a subscription to announcements
func (s *RelayServer) handleSubscribeAnnounces(w moqtransport.ResponseWriter, r *moqtransport.Message) {
	// Accept the subscription to announcements
	if err := w.Accept(); err != nil {
		log.Printf("Failed to accept announcement subscription: %v", err)
		return
	}

	log.Printf("Accepted subscription to announcements for prefix: %v", r.Namespace)
}

// handleTrackStatusRequest processes a track status request
func (s *RelayServer) handleTrackStatusRequest(w moqtransport.ResponseWriter, r *moqtransport.Message) {
	statusHandler, ok := w.(moqtransport.StatusRequestHandler)
	if !ok {
		log.Printf("Track status response writer does not implement status request handler")
		w.Reject(0, "internal error")
		return
	}

	// Set default status values
	statusHandler.SetStatus(0, 0, 0)

	// Accept the request
	if err := w.Accept(); err != nil {
		log.Printf("Failed to send track status: %v", err)
		return
	}

	log.Printf("Processed track status request for namespace: %v, track: %s", r.Namespace, r.Track)
}

// RelayObject relays an object from a publisher to all subscribers
func (s *RelayServer) RelayObject(namespace []string, trackName string, object *moqtransport.Object) {
	namespaceKey := namespaceToKey(namespace)

	// Get all subscribers for this namespace and track
	s.subscriptionLock.RLock()
	defer s.subscriptionLock.RUnlock()

	subscriptionMap, ok := s.subscriptions[namespaceKey]
	if !ok {
		return
	}

	subscribers, ok := subscriptionMap[trackName]
	if !ok {
		return
	}

	// Relay the object to all subscribers
	for _, sub := range subscribers {
		// Try to open a subgroup
		sg, err := sub.subscriber.OpenSubgroup(object.GroupID, object.SubGroupID, 0)
		if err != nil {
			log.Printf("Failed to open subgroup: %v", err)
			continue
		}

		// Write the object to the subgroup
		if _, err := sg.WriteObject(object.ObjectID, object.Payload); err != nil {
			log.Printf("Failed to write object to subgroup: %v", err)
		}

		// Close the subgroup
		sg.Close()
	}
}

// Helper function to convert a namespace slice to a string key
func namespaceToKey(namespace []string) string {
	result := ""
	for i, part := range namespace {
		if i > 0 {
			result += "/"
		}
		result += part
	}
	return result
}
