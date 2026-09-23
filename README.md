# gotor

[![ci](https://github.com/UNC1739/gotor/actions/workflows/ci.yml/badge.svg)](https://github.com/UNC1739/gotor/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/UNC1739/gotor)](https://github.com/UNC1739/gotor/blob/main/go.mod)
[![Release](https://img.shields.io/github/v/release/UNC1739/gotor?include_prereleases)](https://github.com/UNC1739/gotor/releases)

Pure-Go Tor *client* protocol stack plus a local simulated Tor network. Default paths stay on the sim. All binaries build and run in Docker.

Opt-in: `GOTOR_DIR=public` fetches a live microdesc consensus from v3 directory authorities. That is not the default, and it is not what CI runs.

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
| Public v3 onion fetch | `GOTOR_DIR=public`: time-period HSDir ring, BEGIN_DIR `/tor/hs/3/`, intro+rend; `ServeOnion` publishes |
| Congestion control extra-data + XON/XOFF | yes; SENDME v1 still used |
| Conflux (prop 329) | yes; LINK/LINKED/SWITCH in sim |
| C-Tor chutney | optional `chutney` profile |

Egress means: the client builds a 1–3 hop circuit and the **exit relay** dials a TCP destination the sim can reach (localhost in unit tests, `172.28.0.0/16` in compose). That is real onion-encrypted relay traffic, not a stub.

## Run

```sh
make up              # origin + tornet + SOCKS on localhost:9050
curl --socks5-hostname 127.0.0.1:9050 http://172.28.0.10:8080/
make down
```

Env for `gotor`:

| Variable | Default | Meaning |
|---|---|---|
| `GOTOR_DIR` | `127.0.0.1:7000` | sim DirPort, or `public` for v3 authorities |
| `GOTOR_SOCKS` | `0.0.0.0:9050` | SOCKS5 listen |
| `GOTOR_HOPS` | `3` | circuit length |
| `GOTOR_CREATE_FAST` | `1` | `0` disables CREATE_FAST on 1-hop |

Linux binaries (`gotor`, `gotor-net`, `gotor-check`, `origin`) are attached to [GitHub Releases](https://github.com/UNC1739/gotor/releases) on `v*` tags.

## Test

CI (push/`main` + PRs) runs `gofmt`/`go vet` plus the same Docker jobs as locally:

```sh
make test-unit     # Docker go test ./...
make test          # unit + compose integration
make test-chutney  # opt-in: gotor vs three Debian tor relays
```

Compose `test-int` fetches `http://172.28.0.10:8080/` through SOCKS on a 3-hop circuit.

`go test ./...` (inside Docker) covers:

- **crypto**: ntor / ntor-v3, HS keys and descriptors, HKDF, onion layers
- **cell / certs / proto / directory / socks**: encode/decode, handshake identity, consensus + microdescs, SOCKS5
- **client / sim**: 1/2/3-hop HTTP, SENDME, isolation, DESTROY reasons, v3 `.onion` SOCKS, XON/XOFF, conflux

## Layout

```
cell/        cells, RELAY, BEGIN, SENDME, EXTEND2
certs/       ed25519 + RSA CERTS, NETINFO
crypto/      ntor, ntor-v3, CREATE_FAST, onion layers, HS
directory/   consensus, microdescs, sim/public fetch
proto/       TLS link, VERSIONS/CERTS/AUTHENTICATE
client/      circuits, streams, SOCKS isolation, v3 onion
socks/       SOCKS5
sim/         3-relay network + HSDir
cmd/         gotor, gotor-net, gotor-check, origin
```
