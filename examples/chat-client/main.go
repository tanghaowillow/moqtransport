package main

import (
	"context"
	"flag"
	"log"

	"github.com/mengelbart/moqtransport/examples/chat"
)

func main() {
	addr := flag.String("addr", "localhost:8080", "address to connect to")
	wt := flag.Bool("webtransport", false, "Use webtransport instead of QUIC")
	flag.Parse()

	var c *chat.Client
	var err error
	if *wt {
		c, err = chat.NewWebTransportClient(context.Background(), *addr)
	} else {
		c, err = chat.NewQUICClient(context.Background(), *addr)
	}
	if err != nil {
		log.Fatal(err)
	}
	c.Run()
}
