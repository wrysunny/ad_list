package main

import (
	"flag"
	"log"

	"websocket_proxy"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	wsURL := flag.String("ws", "ws://127.0.0.1:43832"+websocket_proxy.WebSocketPath, "websocket server url")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "local socks5 listen addr")
	flag.Parse()

	switch *mode {
	case "server":
		websocket_proxy.WebsocketServer()
	case "client":
		if err := websocket_proxy.RunSocks5Client(*wsURL, *socksAddr); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported mode: %s", *mode)
	}
}
