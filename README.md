# gotor

Pure-Go Tor *client* protocol stack plus a local simulated Tor network. Nothing here talks to the public Tor network. All binaries are built and run in Docker. No C-Tor interop.

## What works

| Feature | Status |
|---|---|
| Directory bootstrap (consensus + descriptors) | yes; microdescs + sim-signed consensus |
| Link handshake (TLS, VERSIONS, CERTS, NETINFO) | yes; relay AUTHENTICATE; CERTS 2/7 RSA cross-cert |
| CREATE_FAST (1-hop) / ntor / ntor-v3 CREATE2+EXTEND2 | yes |
| Exit/egress TCP streams (HTTP, echo, SOCKS5) | yes, via the simulated exit |
| BEGIN_DIR / RELAY_RESOLVE | yes |
| SENDME v1 (circuit digest) / stream SENDME empty | yes |
| PADDING / VPADDING / RELAY_DROP / PADDING_NEGOTIATE | yes; negotiate replies none |
| Path selection (weights, unique, sticky guard, /16) | yes |
| Stream isolation (SOCKS user/pass) | yes |
| RELAY_BEGIN IPv6/IPv4 flags | yes |
| Onion services v3 (sim HSDir + intro + rend) | yes, SOCKS `*.onion`; garbage/v2 still fail |
| Congestion control extra-data + XON/XOFF | yes; SENDME v1 still used |
| C-Tor chutney / public network | **no** |

Egress means: the client builds a 1–3 hop circuit and the **exit relay** dials a TCP destination the sim can reach (localhost in unit tests, `172.28.0.0/16` in compose). That is real onion-encrypted relay traffic, not a stub.

## How we know

`make test-unit` (Docker) covers Tor-style layers:

- **crypto**: ntor / ntor-v3, HS keys and descriptors, HKDF, onion layers
- **cell / certs / proto / directory / socks**: encode/decode, handshake identity checks, consensus + microdescs, SOCKS5
- **client integration**: 1/2/3-hop HTTP, SENDME window, isolation, DESTROY reasons, v3 `.onion` SOCKS, XON/XOFF

Compose `test-int` fetches `http://172.28.0.10:8080/` through SOCKS on a 3-hop circuit. GitHub Actions runs the same Docker unit + integration jobs.

## Commands

```sh
make test-unit   # Docker go test ./...
make test        # unit + compose integration
make up          # origin + tornet + SOCKS on localhost:9050
make down
```
