// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package main

/*
This is a reverse proxy that wraps incoming SSH in TLS, listening on port 443;
this is necessary to trick certain layer 7 firewalls on public wifi systems,
airplanes, and the like. To a passive attacker, the traffic should just look like
uninspectable HTTPS.

Configure ~/.ssh/config like this:

Host myserverproxy
    ProxyCommand openssl s_client -quiet -ign_eof -connect myserver.example.com:443

To run this without root privileges:

sudo setcap cap_net_bind_service=+ep ./server
*/

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	certFlag   = flag.String("cert", "", "File with PEM-encoded certificate and private key")
	domainFlag = flag.String("domain", "localhost", "Domain to autogenerate a self-signed certificate for")
)

const (
	sshHandshakeStartDeadline = 10*time.Second
	// initial version banner, e.g. SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.16
	// technically both sides must immediately send the banner; we violate
	// that by waiting for the client to send before we connect to the local sshd
	sshHandshakeStart = "SSH-"
)

// Socat connects two io.ReadWriteCloser; reads from the first are written
// to the second, and vice versa. Compare the UNIX utility socat(1).
type Socat struct {
	c1 io.ReadWriteCloser
	c2 io.ReadWriteCloser

	errors    chan error
	closeOnce sync.Once
	closeErr  error

	timeout time.Duration
}

// NewSocat starts a two-way copy between two io.ReadWriteCloser.
// `timeout` is the amount of time to wait after an EOF from one side
// for the other side to finish copying; socat(1) defaults to 0.5 seconds,
// but in a reverse proxying context 0 is probably fine.
func NewSocat(c1, c2 io.ReadWriteCloser, timeout time.Duration) *Socat {
	s := &Socat{
		c1:      c1,
		c2:      c2,
		errors:  make(chan error, 2),
		timeout: timeout,
	}
	go s.funnel(c1, c2)
	go s.funnel(c2, c1)
	return s
}

func (s *Socat) funnel(d1, d2 io.ReadWriteCloser) {
	_, err := io.Copy(d1, d2)
	s.errors <- err
	s.Close()
}

// Wait blocks until both io.ReadWriteCloser have been closed. It is not
// necessary to call Wait to ensure that they are closed.
func (s *Socat) Wait() (err error) {
	// return the first error returned by Copy()
	err = <-s.errors
	// block on the sync.Once until close is complete
	s.Close()
	return
}

// Close closes both of the io.ReadWriteCloser.
func (s *Socat) Close() (err error) {
	s.closeOnce.Do(func() {
		if s.timeout != 0 {
			time.Sleep(s.timeout)
		}
		s.closeErr = s.realClose()
	})
	return s.closeErr
}

func (s *Socat) realClose() (err error) {
	e1 := s.c1.Close()
	e2 := s.c2.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func serve(tlsConn net.Conn) {
	handoff := false
	defer func() {
		if !handoff {
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
		if !handoff {
			sshConn.Close()
		}
	}()

	_, err = sshConn.Write(buf[:])
	if err != nil {
		log.Printf("error writing to sshd: %v", err)
		return
	}

	log.Printf("proxying to local sshd from %s", tlsConn.RemoteAddr().String())
	handoff = true
	err = NewSocat(tlsConn, sshConn, 0).Wait()
	if err != nil {
		log.Printf("error from copy: %v", err)
	}
}

func createCert(domainName string) (cert tls.Certificate, err error) {
	validFrom := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := validFrom.Add(validFor)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Internet Widgits Pty Ltd"},
		},
		NotBefore: validFrom,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, domainName)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		err = fmt.Errorf("Failed to create certificate: %w", err)
		return
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		err = fmt.Errorf("Failed to create certificate: %w", err)
		return
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		Leaf:        leaf,
		PrivateKey:  priv,
	}, nil
}

func loadCertificate() (tls.Certificate, error) {
	if *certFlag != "" {
		return tls.LoadX509KeyPair(*certFlag, *certFlag)
	}
	return createCert(*domainFlag)
}

func main() {
	flag.Parse()
	cert, err := loadCertificate()
	if err != nil {
		log.Fatal(err)
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	listener, err := tls.Listen("tcp", ":443", conf)
	if err != nil {
		log.Fatal(err)
	}
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
