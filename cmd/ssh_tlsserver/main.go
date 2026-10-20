// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package main

/*
This is a reverse proxy that wraps incoming SSH in TLS, listening on port 443;
this is necessary to trick certain layer 7 firewalls on public wifi systems,
airplanes, and the like. To a passive attacker, the traffic should just look like
uninspectable HTTPS.

See README.md for configuration information.

To run this without root privileges:

sudo setcap cap_net_bind_service=+ep ./server
*/

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/slingamn/sshobfuscation/internal/lib"
)

var (
	portFlag   = flag.Uint("port", 443, "Port to listen on")
	certFlag   = flag.String("cert", "", "File with PEM-encoded certificate")
	keyFlag    = flag.String("key", "", "File with PEM-encoded private key")
	domainFlag = flag.String("domain", "localhost", "Domain to autogenerate a self-signed certificate for")
)

const (
	sshHandshakeStartDeadline = 10 * time.Second
	// initial version banner, e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16
	// technically both sides must immediately send the banner; we violate
	// that by waiting for the client to send before we connect to the local sshd
	sshHandshakeStart = "SSH-"
)

func serve(tlsConn net.Conn) {
	success := false
	defer func() {
		if !success {
			tlsConn.Close()
		}
	}()

	var buf [len(sshHandshakeStart)]byte
	tlsConn.SetDeadline(time.Now().Add(sshHandshakeStartDeadline))
	_, err := io.ReadFull(tlsConn, buf[:])
	tlsConn.SetDeadline(time.Time{})
	if err != nil {
		log.Printf("incoming TLS connection from %s failed: %v", tlsConn.RemoteAddr().String(), err)
		return
	}
	if string(buf[:]) != sshHandshakeStart {
		log.Printf("incoming TLS connection from %s did not offer SSH handshake", tlsConn.RemoteAddr().String())
		return
	}

	sshConn, err := net.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		log.Printf("error connecting to sshd: %v", err)
		return
	}

	defer func() {
		if !success {
			sshConn.Close()
		}
	}()

	_, err = sshConn.Write(buf[:])
	if err != nil {
		log.Printf("error writing to sshd: %v", err)
		return
	}

	log.Printf("proxying to local sshd from %s", tlsConn.RemoteAddr().String())
	success = true
	err = lib.NewSocat(tlsConn, sshConn, 0).Wait()
	if err != nil {
		log.Printf("error from copy: %v", err)
	}
}

func createCert(domainName string) (cert tls.Certificate, err error) {
	validFrom := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := validFrom.Add(validFor)
	return lib.CreateSelfSignedCert(domainName, validFrom, notAfter)
}

func loadCertConfig() (*tls.Config, error) {
	if *certFlag != "" && *keyFlag != "" {
		certStore := new(lib.AutoreloadingCertStore)
		err := certStore.Initialize(*certFlag, *keyFlag, time.Minute)
		if err != nil {
			return nil, err
		}
		return certStore.TLSConfig(), nil
	} else {
		cert, err := createCert(*domainFlag)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
		}, nil
	}
}

func main() {
	flag.Parse()

	conf, err := loadCertConfig()
	if err != nil {
		log.Fatal(err)
	}
	conf.MinVersion = tls.VersionTLS13

	addr := fmt.Sprintf(":%d", *portFlag)
	listener, err := tls.Listen("tcp", addr, conf)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s\n", addr)
	for {
		tlsConn, err := listener.Accept()
		if err == nil {
			go serve(tlsConn)
		} else {
			// error is likely transient but back off slightly
			log.Printf("error accepting connection: %v", err)
			time.Sleep(time.Second)
		}
	}
}
