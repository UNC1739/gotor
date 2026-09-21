# gotor TODO

One PR per item. Stay on the local Docker sim unless the item says otherwise. Check the box on merge.

## Done

- [x] Cells (link proto 4/5, RELAY, CREATE2/CREATED2, EXTEND2)
- [x] ntor CREATE2/EXTEND2 + AES-CTR/SHA-1 onion layers
- [x] TLS + VERSIONS/CERTS/NETINFO handshake
- [x] Consensus + descriptor fetch (unsigned, subset)
- [x] SOCKS5
- [x] Simulated 3-relay network
- [x] SENDME v0 (circ 1000/100, stream 500/50)

## Protocol (sim-first)

- [x] **CREATE_FAST** — one-hop circuits without ntor (dir fetch / bootstrap)
- [ ] **BEGIN_DIR** — directory HTTP over a circuit, not plaintext DirPort
- [ ] **RELAY_RESOLVE / RELAY_RESOLVED** — SOCKS DNS via the exit
- [ ] **PADDING / VPADDING / RELAY_DROP** — link + long-range padding cells
- [ ] **SENDME v1** — authenticated circuit SENDMEs (rolling digest)
- [ ] **ntor-v3** — extra-data handshake (Relay=4)
- [ ] **CREATE2/EXTEND2 ntor-v3 path** — client prefers v3 when advertised
- [ ] **Relay-to-relay AUTHENTICATE** — EXTEND initiator proves identity
- [ ] **RSA identity cross-cert (CERTS type 2/7)** — legacy NODEID binding
- [ ] **Microdescriptors** — `m` lines + `/tor/micro/d/`
- [ ] **Consensus signatures** — verify `directory-signature` (or sim-signed)
- [ ] **Path selection** — bandwidth weights, /16, unique relays, guard sticky
- [ ] **Stream isolation** — SOCKS isolation flags → separate circuits
- [ ] **DESTROY / TRUNCATE reasons** — propagate and surface to SOCKS
- [ ] **RELAY_BEGIN flags** — IPv6 okay / IPv4 not okay / prefer IPv6

## Onion services (v3, sim-only)

- [ ] **HS keys** — blinded ed25519, subcredential
- [ ] **HS descriptor** — build/parse/encrypt (first/second layer)
- [ ] **HSDir** — store/fetch descriptors in the sim
- [ ] **INTRO** — ESTABLISH_INTRO / INTRODUCE1 / INTRODUCE2
- [ ] **RENDEZVOUS** — ESTABLISH_RENDEZVOUS / RENDEZVOUS1 / RENDEZVOUS2
- [ ] **Client .onion** — SOCKS to `*.onion` via intro+rend (drop `ErrOnion`)

## Hardening / interop

- [ ] **C-Tor chutney** — optional compose profile; gotor client vs real `tor` relays
- [ ] **Congestion control (prop 324)** — ntor-v3 CC extension, XON/XOFF
- [ ] **Circuit padding (prop 254)** — PADDING_NEGOTIATE relay msgs
- [ ] **Conflux (prop 329)** — later, if ever

## Housekeeping

- [ ] **CI** — GitHub Actions: `docker compose` unit + integration
- [ ] **README** — keep the capability table in sync with this file
