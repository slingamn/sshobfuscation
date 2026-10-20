// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/url"
	"os"

	"github.com/slingamn/sshobfuscation/internal/lib"

	"github.com/slingamn/sshobfuscation/pkg/httpclient"
)

var (
	insecureFlag = flag.Bool("insecure", false, "Disable TLS certificate verification")
)

func main_() (code int) {
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Printf("insufficient arguments\n")
		return 1
	}
	addr := args[0]
	var conf *tls.Config
	if *insecureFlag {
		conf = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	u, err := url.Parse(addr)
	if err == nil && u.Scheme == "https" {
		return proxyWSS(u, conf)
	} else {
		return proxyTLS(addr, conf)
	}
}

func proxyTLS(addr string, conf *tls.Config) (code int) {
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		log.Printf("error dialing remote server %s: %v\n", addr, err)
		return 1
	}
	socat := lib.NewSocat(conn, lib.StdioRWC{}, 0)
	socat.Wait()
	return 0
}

func proxyWSS(u *url.URL, conf *tls.Config) (code int) {
	success := false
	hostPort, _ := lib.GetHostPort(u)
	netConn, err := tls.Dial("tcp", hostPort, conf)
	if err != nil {
		log.Printf("error dialing remote server %s: %v\n", u.String(), err)
		return 1
	}

	defer func() {
		if !success {
			netConn.Close()
		}
	}()

	unread, err := httpclient.PerformWSClientHandshake(netConn, u)
	if err != nil {
		log.Printf("error from handshake to remote server %s: %v\n", u.String(), err)
		return 1
	}

	if len(unread) != 0 {
		os.Stdout.Write(unread)
	}

	success = true
	socat := lib.NewSocat(netConn, lib.StdioRWC{}, 0)
	socat.Wait()
	return 0
}

func main() {
	os.Exit(main_())
}
