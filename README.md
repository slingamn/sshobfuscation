SSH obfuscation tools
=====================

These are tools in memory-safe Go for obfuscating ssh traffic inside
TLS on port 443, in order to defeat application-level firewalls that
detect the ssh protocol (found in some public WiFi systems, airplanes
and the like). To such firewalls (as long as they do not attempt
active TLS inspection via MITM attacks, which is not common practice), the
traffic should appear indistinguishable from a long-running WebSocket
connection over TLS.

There are two implementations:

* `ssh_tlsserver` wraps the SSH protocol in an outer layer of TLS. This is
  the simplest solution if you're not already running an httpd on port
  443, since it can listen directly on 443, terminate TLS, and forward to
  the sshd.
* `ssh_httpserver` performs a WebSocket handshake, i.e. it consumes a
  `HTTP/1.1 GET` request and associated headers from the client,
  returns a `HTTP/1.1 101 Switching Protocols` response with appropriate
  headers, then forwards the connection to the sshd. This can be used with an
  existing reverse proxy (such as nginx or Caddy) that listens on port 443
  and terminates TLS. As long as a correct WebSocket handshake was exchanged
  (and periodic layer 7 keepalives are sent during the lifetime of the
  persistent connection), the reverse proxy does not care whether the data
  sent over the connection is WebSocket frames or some other protocol
  (in our case, SSH).

Both implementations have only one layer of tunnelling (after the
initial handshake, the SSH protocol is tunneled inside TLS, not inside
WebSocket frames inside TLS), and they inherit all the security properties
of the SSH protocol (barring potential memory corruption and resource
exhaustion issues in the TLS and HTTP implementations, they should not
increase the attack surface of the host at all).

Configuring `ssh_tlsserver`
---------------------------

Run `make` to build all binaries. Allow `ssh_tlsserver` to bind to 443 without
running as root:

```
sudo setcap cap_net_bind_service=+ep ./bin/ssh_tlsserver
```

The simplest configuration is to allow `ssh_tlsserver` to generate a
self-signed certificate, in which case it can be invoked with no arguments.
You can also use the `--cert` and `--key` flags to specify a TLS certificate to
use, which will autoreload on change.

Configure `~/.ssh/config` like this:

```
Host myserverproxy
    ProxyCommand openssl s_client -quiet -ign_eof -connect myserver.example.com:443
```

or, to use this project's proxy binary:

```
Host myserverproxy
    ProxyCommand ~/bin/ssh_proxycommand --insecure myserver.example.com:443
```

You can then connect via `ssh myserverproxy`.

Both of these configurations disable verification of the TLS certificate,
which should not reduce security given that one can rely instead on
verification of the SSH host key.

See `distrib/ssh_tlsserver.service` for an example systemd unit file.

Configuring `ssh_httpserver`
----------------------------

Run `make` to build all binaries.

The simplest and highest-performance configuration is to have `ssh_httpserver`
listen on a Unix domain socket, e.g.

```
ssh_httpserver --listen /tmp/ssh_http_proxy_sock
```

nginx can then be configured to forward a designated path to the server.
Although keeping the path secret is not necessary for security, it can
help to avoid denial-of-service attacks:

```
	location /ssh_dGjlT09TOfkNXdYVtMQeOQ {
		proxy_pass http://unix:/tmp/ssh_http_proxy_sock;
		proxy_http_version 1.1;
		proxy_read_timeout 600s;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection "Upgrade";
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
	}
```

Configure `~/.ssh/config` like this:

```
Host myserverproxy
    ProxyCommand ~/bin/ssh_proxycommand https://myserver.example.com/ssh_dGjlT09TOfkNXdYVtMQeOQ
    # ensure that data is exchanged periodically, to stop nginx from closing the connection:
    ServerAliveInterval 180
```

You can then connect via `ssh myserverproxy`.

See `distrib/ssh_httpserver.service` for an example systemd unit file.
