// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package main

/*
This is a reverse proxy designed to sit between nginx (or similar) and sshd.
It accepts a proxied websocket connection from nginx, conducts the websocket
HTTP 1.1 request/response handshake, but instead of interpreting the remaining
stream data as websocket frames, it connects it bidirectionally to the sshd.
This allows the nginx to perform its normal multiplexing on port 443 while
forwarding the traffic to the sshd. To a passive attacker, the traffic should
just look like uninspectable HTTPS.

Configure ~/.ssh/config like this:

Host myserverproxy
	ProxyCommand sshobfuscation_proxycommand https://myserver.example.com/secret_path
	ServerAliveInterval 300

Configure nginx like this:

	location /secret_path {
		proxy_pass http://unix:/tmp/sshobfuscation;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection "Upgrade";
		proxy_read_timeout 10m;
	}

*/

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/slingamn/sshobfuscation/pkg/httpserver"
)

var (
	listenFlag = flag.String("listen", "", "Address to listen on (e.g. `:443`, `/tmp/sock`)")
	pathFlag   = flag.String("path", "", "Required path of the HTTP upgrade request (by default, any path is accepted)")
)

func main() {
	flag.Parse()
	addr := *listenFlag
	family := "tcp"
	if strings.HasPrefix(addr, "/") {
		family = "unix"
		os.Remove(addr)
	}

	listener, err := net.Listen(family, addr)
	if err != nil {
		log.Fatal(err)
	}
	if family == "unix" {
		os.Chmod(addr, 0777)
	}

	log.Printf("Listening on %s address %s\n", family, addr)

	srv := http.Server{
		Handler: &httpserver.WSToStreamHandler{
			LookupAddr: func(u *url.URL) (family, address string) {
				return "tcp", "127.0.0.1:22"
			},
			HandshakeTimeout: 10 * time.Second,
			RequirePath:      *pathFlag,
		},
	}

	if err := srv.Serve(listener); err != http.ErrServerClosed {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
