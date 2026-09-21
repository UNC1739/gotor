# gotor

Pure-Go Tor *client* protocol stack plus a local simulated Tor network. Nothing here talks to the public Tor network. All binaries are built and run in Docker.

## What works

| Feature | Status |
|---|---|
| Directory bootstrap (consensus + descriptors) | yes |
| Link handshake (TLS, VERSIONS, CERTS, NETINFO) | yes |
| ntor CREATE2 / EXTEND2 circuits | yes |
| Exit/egress TCP streams (HTTP, echo, SOCKS5) | yes, via the simulated exit |
| SENDME v0 flow control (circ 1000/100, stream 500/50) | yes |
| Onion / hidden services (`.onion`) | **no** — client returns `ErrOnion` |

Egress means: the client builds a 1–3 hop circuit and the **exit relay** dials a TCP destination the sim can reach (localhost in unit tests, `172.28.0.0/16` in compose). That is real onion-encrypted relay traffic, not a stub.

## How we know

`go test ./...` (run inside Docker) covers Tor-style layers:

- **crypto**: ntor round-trip, bad NODEID/KEYID/AUTH, HKDF matching the spec recurrence, onion layers, digest false-recognized, sequential cells
- **cell / certs / proto / directory / socks**: encode/decode, handshake identity checks, consensus parsing, SOCKS5 IPv4+domain
- **client integration** (chutney-like): 1/2/3-hop HTTP egress, IPv4 BEGIN, 80KiB echo, 280KiB SENDME window, multiplexed streams, connect refused, `.onion` rejected, CERTS identity mismatch, SOCKS5 fetch

Compose `test-int` fetches `http://172.28.0.10:8080/` through SOCKS on a 3-hop circuit.

## Commands

```sh
make test        # unit + integration (Docker only)
make up          # origin + tornet + SOCKS on localhost:9050
make down
```
