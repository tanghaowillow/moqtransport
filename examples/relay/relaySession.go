package main

import (
	"github.com/mengelbart/moqtransport"
)

// relaySession represents a client that has published a track
type relaySession struct {
	namespace   []string
	trackName   string
	remoteTrack moqtransport.RemoteTrack
	session     *moqtransport.Session
	sessionID   uint64
	subscribeID uint64
	trackAlias  uint64
}

func (s *relaySession) CloseWithError(code uint64, reason string) error {
	return s.remoteTrack.Close()
	// notify subcribers
}

// receive objects and relay to subscribers
func (s *relaySession) run() {

}
