// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package httpserver

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/slingamn/sshobfuscation/internal/lib"
)

// WSToStreamHandler is a http.Handler that processes a WebSocket upgrade
// request, then forwards the resulting connection to an arbitrary outgoing
// stream connection (i.e. not necessarily the WebSocket frames protocol).
type WSToStreamHandler struct {
	// LookupAddr is a callback allowing an arbitrary mapping of URLs to
	// outgoing connection addresses.
	LookupAddr func(u *url.URL) (family, address string)
	// RequirePath optionally restricts forwarding to a specific GET path
	// (e.g. if this is not provided externally by a router/multiplexer or
	// reverse proxy).
	RequirePath string
	// HandshakeTimeout is an optional timeout for writing the HTTP 101
	// (switching protocols) response.
	HandshakeTimeout time.Duration
	// Logger is an optional custom logger for errors.
	Logger *log.Logger
}

var _ http.Handler = (*WSToStreamHandler)(nil)

func (h *WSToStreamHandler) doLookupAddr(u *url.URL) (family, address string) {
	defer func() {
		if r := recover(); r != nil {
			h.logPrintf("panic looking up dial address for %s: %v\n", u.String(), r)
		}
	}()

	return h.LookupAddr(u)
}

func (h *WSToStreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	family, address := h.doLookupAddr(r.URL)
	if family == "" || address == "" {
		h.errorResponse(w, r, http.StatusNotFound, "not found")
		return
	}

	if h.RequirePath != "" && r.URL.Path != h.RequirePath {
		h.errorResponse(w, r, http.StatusNotFound, "not found")
		return
	}

	w.Header().Set("Sec-Websocket-Version", "13")

	const badHandshake = "websocket: the client is not using the websocket protocol: "

	if !lib.TokenListContainsValue(r.Header, "Connection", "upgrade") {
		h.errorResponse(w, r, http.StatusBadRequest, badHandshake+"'upgrade' token not found in 'Connection' header")
		return
	}

	if !lib.TokenListContainsValue(r.Header, "Upgrade", "websocket") {
		w.Header().Set("Upgrade", "websocket")
		h.errorResponse(w, r, http.StatusUpgradeRequired, badHandshake+"'websocket' token not found in 'Upgrade' header")
		return
	}

	if r.Method != http.MethodGet {
		h.errorResponse(w, r, http.StatusMethodNotAllowed, badHandshake+"request method is not GET")
		return
	}

	if !lib.TokenListContainsValue(r.Header, "Sec-Websocket-Version", "13") {
		h.errorResponse(w, r, http.StatusBadRequest, "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header")
		return
	}

	challengeKey := r.Header.Get("Sec-Websocket-Key")
	if !lib.IsValidChallengeKey(challengeKey) {
		h.errorResponse(w, r, http.StatusBadRequest, "websocket: not a websocket handshake: 'Sec-WebSocket-Key' header must be Base64 encoded value of 16-byte in length")
		return
	}

	// any origin header is disallowed, to prevent DoS attacks from browsers
	// (our custom ProxyCommand will omit the header)
	if r.Header.Get("Origin") != "" {
		h.errorResponse(w, r, http.StatusBadRequest, "websocket: must not send origin header")
	}

	success := false

	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		h.errorResponse(w, r, http.StatusInternalServerError, "websocket: hijack: "+err.Error())
		return
	}

	defer func() {
		if !success {
			netConn.Close()
		}
	}()

	localConn, err := net.Dial(family, address)
	if err != nil {
		h.errorResponse(w, r, http.StatusInternalServerError, "local connection failed: "+err.Error())
		return
	}

	defer func() {
		if !success {
			localConn.Close()
		}
	}()

	// this should not be possible, since the client should wait for our HTTP
	// response before sending
	if bufLen := brw.Reader.Buffered(); bufLen != 0 {
		buf := make([]byte, bufLen)
		// cannot error
		io.ReadFull(brw.Reader, buf)
		localConn.Write(buf)
	}

	p := make([]byte, 0, 256)
	p = append(p, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	p = append(p, lib.ComputeAcceptKey(challengeKey)...)
	p = append(p, "\r\n\r\n"...)

	if h.HandshakeTimeout != 0 {
		netConn.SetWriteDeadline(time.Now().Add(h.HandshakeTimeout))
	}
	_, err = netConn.Write(p)
	if err != nil {
		h.logPrintf("write error: %v\n", err)
		return
	}
	netConn.SetWriteDeadline(time.Time{})

	h.logPrintf("Accepted proxied connection from %s\n", r.RemoteAddr)

	// this uses io.Copy which should specialize to sendfile(2) or splice(2),
	// i.e. a pure kernelspace copy between the incoming and outgoing connections.
	// spin off the copies and return immediately from this handler:
	success = true
	lib.NewSocat(netConn, localConn, 0)
}

func (h *WSToStreamHandler) logPrintf(format string, v ...any) {
	logger := h.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf(format, v...)
}

func (h *WSToStreamHandler) errorResponse(w http.ResponseWriter, r *http.Request, status int, reason string) {
	h.logPrintf("Error %d from %s: %s\n", status, r.RemoteAddr, reason)
	http.Error(w, http.StatusText(status), status)
	w.Write([]byte(reason))
}
