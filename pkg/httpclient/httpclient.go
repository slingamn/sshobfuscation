// Copyright (c) 2021 Shivaram Lingamneni
// released under the MIT license

package httpclient

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/slingamn/sshobfuscation/internal/lib"
)

// PerformWSClientHandshake sends an outgoing WebSocket handshake and consumes
// the HTTP response. On success, it returns some initial non-HTTP data that was
// incidentally read along with the HTTP response (and must be processed before
// reading further from the underlying connection, which is otherwise ready for
// use).
func PerformWSClientHandshake(netConn net.Conn, u *url.URL) (unread []byte, err error) {
	key := lib.GenerateChallengeKey()
	acceptKey := lib.ComputeAcceptKey(key)

	var buf bytes.Buffer
	buf.Grow(256)

	fmt.Fprintf(&buf, "GET %s HTTP/1.1\r\n", u.Path)
	fmt.Fprintf(&buf, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&buf, "User-Agent: Go-http-client/1.1\r\n")
	fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(&buf, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&buf, "Upgrade: websocket\r\n\r\n")
	// intentionally omit Origin to prove we're not a browser

	_, err = netConn.Write(buf.Bytes())
	if err != nil {
		return
	}

	// validate that we get HTTP/1.1 101 Switching Protocols, and also the accept key:
	// headers we are not validating: Connection: Upgrade, Upgrade: WebSocket
	success := false
	br := bufio.NewReader(io.LimitReader(netConn, 16*1024))
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 101 ") {
		err = fmt.Errorf("Invalid response line (err=%v): %s", err, line)
		return
	}

	for {
		// consume until final blank line
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		success = success || strings.Contains(line, acceptKey)
	}

	if !success {
		err = fmt.Errorf("Response did not contain accepted challenge response key")
		return
	}

	if brLen := br.Buffered(); brLen != 0 {
		unread = make([]byte, brLen)
		// cannot error
		io.ReadFull(br, unread)
	}

	return unread, nil
}
