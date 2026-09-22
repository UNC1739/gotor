# gotor TODO

One PR per checkbox. Stay on the local Docker sim unless the item says otherwise. Check the box on merge, not on branch. Do not talk to the public Tor network. Run tests only via Docker (`make test-unit` / `docker compose`).

Honest scope: a client-shaped subset (cells, ntor, onion layers, SOCKS5, SENDME). No v3 onion services and no C-Tor interop until those items. Do not volunteer extras (tighter windows, extra handshake, public-network code).

---

## Done (on `main`)

- [x] Cells (link proto 4/5, RELAY, CREATE2/CREATED2, EXTEND2)
- [x] ntor CREATE2/EXTEND2 + AES-CTR/SHA-1 onion layers
- [x] TLS + VERSIONS/CERTS/NETINFO handshake
- [x] Consensus + descriptor fetch (unsigned, subset)
- [x] SOCKS5
- [x] Simulated 3-relay network
- [x] SENDME v0 (circ 1000/100, stream 500/50)
- [x] CREATE_FAST (#1) — 1-hop circuits use CREATE_FAST/KDF-TOR; multi-hop still ntor
- [x] BEGIN_DIR (#2) — `Circuit.DialDir` + sim DirPort splice
- [x] RELAY_RESOLVE / RELAY_RESOLVED (#3) — `Circuit.Resolve`
- [x] PADDING / VPADDING / RELAY_DROP (#4)
- [x] SENDME v1 (#5) — authenticated circuit SENDMEs (rolling digest)

Current `main` baseline:

- Bootstrap is still plaintext HTTP to the sim DirPort (`directory.Fetch`). BEGIN_DIR can fetch the same docs over a circuit.
- 1-hop: CREATE_FAST. 2–3 hop: ntor CREATE2 + ntor EXTEND2. `PickPath` takes `pool[0]` per role.
- Link handshake is VERSIONS + CERTS (ed25519 types 4/5) + AUTH_CHALLENGE (ignored by initiator) + NETINFO. No AUTHENTICATE. No RSA CERTS 2/7.
- BEGIN payload is `host:port\0` plus four zero flag bytes.
- DESTROY reasons are hardcoded (1/2/6/11). TRUNCATE unused.
- Circuit SENDME is v1 (20-byte digest); stream SENDME is empty.
- `.onion` → `ErrOnion`. Consensus `directory-*` lines skipped. No bandwidth weights, no microdescs, no signatures.

---

## Protocol (sim-first)

Each remaining item: spec refs, what exists, what to build, tests, out of scope. Merged items above are not re-opened.

### CREATE_FAST

- [x] **CREATE_FAST** — one-hop circuits without ntor (dir fetch / bootstrap)

**Spec:** [CREATE_FAST](https://spec.torproject.org/tor-spec/create-created-cells.html#create_fast). Cells 5/6. Handshake: client 20-byte X, relay 20-byte Y + KH. Keys via KDF-TOR (`K = g^x` analogue is `KDF-TOR(X | Y)` → KH, Df, Db, Kf, Kb). CircID rules unchanged.

**Now:** only CREATE2/CREATED2 ntor (`HTypeNtor = 0x0002`). No CREATE_FAST cell builders. Client first hop always ntor.

**Do:**

1. `cell.CreateFast` / `ParseCreateFast` / `CreatedFast` / `ParseCreatedFast` (X 20, Y 20, KH 20).
2. `crypto.KDFTor` matching tor-spec (SHA-1 counter KDF, same layout as TAP leftover keys).
3. Sim: on CREATE_FAST, reply CREATED_FAST, install hop keys. Reject CREATE_FAST on a circuit that already exists.
4. Client: 1-hop circuits use CREATE_FAST. Multi-hop still ntor CREATE2 + EXTEND2.
5. CREATE_FAST circuits have no TAP/ntor extra info; SENDME v0 is allowed (v1 needs a later item).

**Tests:** cell round-trip; KDF vector if we mint one; e2e 1-hop HTTP via CREATE_FAST; 3-hop still ntor.

**Out of scope:** TAP CREATE, using CREATE_FAST for hop 2+.

---

### BEGIN_DIR

- [x] **BEGIN_DIR** — directory HTTP over a circuit, not plaintext DirPort

**Spec:** [Opening a directory stream](https://spec.torproject.org/tor-spec/opening-streams.html#opening-a-directory-stream). RELAY_BEGIN_DIR (cmd 13), empty body, nonzero StreamID. CONNECTED has empty body (no addr). END reason 13 = not a directory.

**Now:** bootstrap is `http://DirAddr/tor/...`. Relays have no DirAddr wiring on `main`. `RelayBeginDir = 13` constant exists.

**Do:**

1. Sim: each relay gets the shared directory HTTP address. On BEGIN_DIR, dial that TCP HTTP endpoint (ignore exit policy). If no DirPort/DirAddr, END 13.
2. Client: `Circuit.DialDir()` sends BEGIN_DIR, waits CONNECTED.
3. `directory.HTTPGet(io.ReadWriter, path)` HTTP/1.0 + `Connection: close`, parse status + body.
4. Optional: fetch consensus over a 3-hop DialDir (plaintext DirPort may remain for bootstrap until this lands).

**Tests:** 3-hop DialDir GET `/tor/status-vote/current/consensus`, `ParseConsensus` → 3 relays.

**Out of scope:** encrypted dir connections, compression, BEGIN_DIR to public authorities.

---

### RELAY_RESOLVE / RELAY_RESOLVED

- [x] **RELAY_RESOLVE / RELAY_RESOLVED** — SOCKS DNS via the exit

**Spec:** [Remote hostname lookup](https://spec.torproject.org/tor-spec/remote-hostname-lookup.html). RESOLVE: hostname + NUL, nonzero distinct StreamID, no stream created. RESOLVED: repeating `(Type u8, Len u8, Value, TTL u32be)`. Types: 0x00 hostname, 0x04 IPv4, 0x06 IPv6, 0xF0 transient error, 0xF1 nontransient. Any error type ⇒ no other answers. IPv4 answers first if any.

**Now:** constants `RelayResolve=11`, `RelayResolved=12`. No encode/parse, no client API, sim ignores.

**Do:**

1. `cell.EncodeResolve` / `ParseResolve` / `EncodeResolved` / `ParseResolved`.
2. Sim exit: `net.LookupIP`, IPv4 first, TTL 60, error 0xF1 + `"Error resolving hostname"` on failure.
3. `Circuit.Resolve(host) ([]net.IP, error)` — allocate StreamID, waiter only (do not register a live stream), wait RESOLVED.
4. SOCKS need not change in this PR (BEGIN still sends hostname). Resolve API is the protocol piece.

**Tests:** cell round-trip; e2e `Resolve("localhost")` on 3-hop contains 127.0.0.1 or ::1.

**Out of scope:** reverse in-addr.arpa, SOCKS UDP associate.

---

### PADDING / VPADDING / RELAY_DROP

- [x] **PADDING / VPADDING / RELAY_DROP** — link + long-range padding cells

**Spec:** [Link padding](https://spec.torproject.org/tor-spec/flow-control.html#link-padding), cell commands 0 / 128, relay DROP cmd 10. CircID 0 for PADDING/VPADDING. DROP is a recognized relay message; body ignored; does not affect SENDME windows.

**Now:** constants exist. Channel read loop and handshake already skip PADDING/VPADDING. Sim `handleCell` ignores them. RELAY_DROP falls through as unhandled (dropped). No constructors, no client send, no e2e.

**Do:**

1. `cell.Padding()` (fixed 509-byte body, CircID 0) and `cell.Vpadding(body)` (variable).
2. `Circuit.SendPadding` / `SendVpadding(n)` / `Drop(hop)` (RELAY_DROP to that hop).
3. Client `handleRelay`: ignore RelayDrop (do not put StreamID 0 DROP on `ctrl`).
4. Sim `handleRecognized`: explicit RelayDrop case.

**Tests:** cell round-trips (PADDING length 4+1+509, VPADDING 4+1+2+n); e2e padding + DROP at each hop then HTTP still works.

**Out of scope:** PADDING_NEGOTIATE timeouts, padding-spec machines (later item).

---

### SENDME v1

- [x] **SENDME v1** — authenticated circuit SENDMEs (rolling digest)

**Spec:** [SENDME message format](https://spec.torproject.org/tor-spec/flow-control.html#sendme-message-format). Circuit SENDME StreamID=0. Body: VERSION 1, DATA_LEN 20, DIGEST 20 (SHA-1 running digest after the DATA cell that hit a multiple of 100). Mismatch ⇒ DESTROY. Stream SENDMEs stay empty.

**Now:** v0 empty circuit SENDMEs. `NeedSendme` 1000/100 and 500/50. Hop SHA-1 running digest exists (`fDigest`/`bDigest`) but is not snapshotted.

**Do:**

1. `Hop.ForwardDigest` / `BackwardDigest` → 20-byte `Sum`.
2. `cell.EncodeSendmeV1` / `ParseSendme`. Reject circuit SENDME that is not v1.
3. Remember digest at **encrypt/seal + write** under the same mutex (otherwise DATA/SENDME reorder desyncs the digest). FIFO of expected digests, one per 100 DATA cells.
4. Receiver snapshots digest of the DATA cell that tripped `NeedSendme` and puts it in the SENDME.
5. Hold hop seal+write under one mutex (already required for v0 correctness).

**Tests:** encode/parse; crypto both sides agree after BEGIN+100 DATA; existing 280KiB echo still passes; mismatch tears the circuit.

**Out of scope:** sendme_emit_min_version consensus params, CREATE_FAST exemption (that PR may keep v0 on fast circuits).

---

### ntor-v3

- [ ] **ntor-v3** — extra-data handshake (Relay=4)

**Spec:** [ntor-v3](https://spec.torproject.org/tor-spec/create-created-cells.html#ntor-v3), [subprotocol Relay=4](https://spec.torproject.org/tor-spec/subprotocol-versioning.html). CREATE2/CREATED2 HTYPE **0x0003**. Proto ID `ntor3-curve25519-sha3-256-1`. Client message: encrypted+authenticated extra-data blob (length-prefixed). Server reply: Y, AUTH, encrypted extra-data. Circuit keys from ntor-v3 KDF (SHAKE-256 / SHA3 as specified), still AES-CTR + SHA-1 onion for ordinary circuits.

**Now:** only HTYPE 0x0002 ntor (`crypto/ntor.go`, HMAC-SHA256, proto `ntor-curve25519-sha256-1`). No extra-data.

**Do:**

1. `crypto` ntor-v3 client handshake + server `Reply` with extra-data in and out (start with empty extra-data so the handshake stands alone).
2. Reject degenerate X25519, NODEID/KEYID/AUTH mismatch analogue.
3. `NewHop` from ntor-v3 key blob (same Df/Db/Kf/Kb/KH layout unless spec says otherwise).
4. Sim accepts HTYPE 0x0003 on CREATE2/EXTEND2 when this PR also wires sim (or land crypto+tests here and wire in the next item — prefer **crypto + vectors in this PR**, wire in the next).

**Tests:** round-trip empty extra-data; bad AUTH; extra-data encrypt/decrypt; hop can seal/recognize one relay cell.

**Out of scope:** congestion-control extra-data (prop 324 item), ntor-v3 on onion-service rdv (SHA3-256 digest hops).

---

### CREATE2/EXTEND2 ntor-v3 path

- [ ] **CREATE2/EXTEND2 ntor-v3 path** — client prefers v3 when advertised

**Depends on:** ntor-v3 crypto.

**Spec:** same as ntor-v3. Descriptors advertise `proto` / `pr` Relay=4. Client uses 0x0003 if the hop advertises it, else 0x0002.

**Now:** descriptors have ntor-onion-key + ed25519 id only. No proto line. Client always 0x0002.

**Do:**

1. Sim descriptors (and consensus `pr` if present) advertise `Relay=1-4` (or at least 4).
2. `directory.Relay` grows a proto set; parse `pr` / `protocols` / descriptor `proto`.
3. Client CREATE2/EXTEND2: HTYPE 0x0003 if Relay≥4, else 0x0002.
4. Sim CREATE2 and EXTEND2 handle both HTYPEs.
5. 1-hop CREATE_FAST unchanged.

**Tests:** 3-hop HTTP with all hops v3; mixed path (one hop without Relay=4 falls back to ntor); reject v3 handshake with v2 keys.

**Out of scope:** proto negotiation for Link/HSDir/etc.

---

### Relay-to-relay AUTHENTICATE

- [ ] **Relay-to-relay AUTHENTICATE** — EXTEND initiator proves identity

**Spec:** [AUTHENTICATE cells](https://spec.torproject.org/tor-spec/negotiating-channels.html#AUTHENTICATE-cells), [AUTH_CHALLENGE](https://spec.torproject.org/tor-spec/negotiating-channels.html#AUTH-CHALLENGE-cells). Initiator that is a relay MUST send CERTS + AUTHENTICATE after AUTH_CHALLENGE. Clients MUST NOT. Method: Ed25519-SHA256-RFC5705 (type 0x0008 in current spec). RFC5705 TLS exporter binds the auth to the TLS session.

**Now:** `HandshakeInitiator` (used by client **and** sim EXTEND) reads CERTS/AUTH_CHALLENGE/NETINFO and only replies NETINFO. Sim EXTEND therefore never authenticates.

**Do:**

1. Split initiator handshake: client path (no AUTHENTICATE) vs relay path (CERTS + AUTHENTICATE).
2. Encode/verify AUTHENTICATE Ed25519 (CID, SID, CID_ED, SID_ED, exporter, SIG).
3. Sim `doExtend`: use relay initiator handshake with the extending relay’s identity keys.
4. Sim responder: if AUTHENTICATE missing from a relay-to-relay link, fail the handshake (client links still OK without it).

**Tests:** extend 3-hop still works; forged AUTHENTICATE fails; client links still skip AUTHENTICATE.

**Out of scope:** RSA authenticator types, AUTHENTICATE from the gotor SOCKS client.

---

### RSA identity cross-cert (CERTS type 2/7)

- [ ] **RSA identity cross-cert (CERTS type 2/7)** — legacy NODEID binding

**Spec:** [CERTS cells](https://spec.torproject.org/tor-spec/negotiating-channels.html#CERTS-cells). Type 2 = RSA identity cert. Type 7 = RSA identity key certified by ed25519 identity (or the cross-cert that binds RSA ID to ed25519). Needed for C-Tor interop and SHA-1 identity digest (`Identity [20]byte`) provenance.

**Now:** CERTS only type 4 (ed25519 identity→signing) and 5 (signing→TLS). `Identity` in consensus is a random 20-byte id, not SHA-1(RSA key).

**Do:**

1. Generate a per-relay RSA-1024 or RSA-2048 identity (sim-only; 1024 is what old Tor used — prefer 2048 if C-Tor will accept).
2. CERTS type 2 + type 7 cross-cert. Verify chain: TLS ← ed25519 signing ← ed25519 identity, and RSA ID ↔ ed25519.
3. Consensus `r` identity digest = SHA-1(ASN.1 RSA public key) once this exists.
4. Client: if type 2/7 present, verify; if absent, keep current ed25519-only behavior (sim can always send them).

**Tests:** handshake with 2/7 present; mismatch type 7 fails; identity digest matches consensus `r` field.

**Out of scope:** TAP onion-key, obsolete link proto 1–3.

---

### Microdescriptors

- [ ] **Microdescriptors** — `m` lines + `/tor/micro/d/`

**Spec:** [dir-spec microdescriptors](https://spec.torproject.org/dir-spec/microdescriptor-consensus.html). Microdesc consensus `m` line = base64 SHA256 of the microdesc. Fetch `GET /tor/micro/d/<D1>-<D2>-...`. Microdesc contains `onion-key` (omit in sim if TAP unused), `ntor-onion-key`, `id ed25519`, family, `p`/`p6`.

**Now:** full descriptors only (`/tor/server/all`). No `m` lines. Client always `ParseDescriptors`.

**Do:**

1. Sim: build microdescs, SHA256, `m` lines in consensus (or a `/tor/status-vote/current/consensus-microdesc` flavor).
2. Endpoint `/tor/micro/d/...`.
3. Client: fetch micro consensus + micros, fill `NTorOnionKey` / `Ed25519ID` / exit policy.
4. Keep full descriptors working so existing tests pass (flavor switch or fetch both).

**Tests:** parse `m` + micro body; bootstrap via micros builds a 3-hop circuit.

**Out of scope:** consensus method diffs, compression.

---

### Consensus signatures

- [ ] **Consensus signatures** — verify `directory-signature` (or sim-signed)

**Spec:** [dir-spec validating consensus](https://spec.torproject.org/dir-spec/consensus-formats.html). `directory-signature <alg> <identity> <signing-key-digest>` then base64 signature. Signed portion is the document through `directory-signature` (exact hashing rules in dir-spec). Sim may be a single authority.

**Now:** `ParseConsensus` skips `directory-*` lines. Sim consensus is unsigned text.

**Do:**

1. Sim authority key (ed25519 or RSA per flavor we emit). Attach `directory-signature`.
2. Client: verify at least one valid signature; reject truncated/tampered consensus.
3. Do not verify against a hardcoded live Tor dirkey.

**Tests:** good signature accepts; flipped byte rejects; missing signature rejects once this is on.

**Out of scope:** multi-authority voting, bandwidth-file headers, real Tor dirauths.

---

### Path selection

- [ ] **Path selection** — bandwidth weights, /16, unique relays, guard sticky

**Spec:** [path-spec](https://spec.torproject.org/path-spec/index.html). Weighted random by consensus bandwidth and `bandwidth-weights` (Wgg, Wgm, Weg, …). Distinct relays. No two in the same IPv4 /16. Guard: sticky first hop (reuse across circuits). Exit must allow the port (later; sim exits accept *).

**Now:** `PickPath` uses `pool[0]` for Guard / Middle / Exit. Sim has exactly 3 relays, so uniqueness is accidental. No weights, no /16 check, no guard pin.

**Do:**

1. Parse `w Bandwidth=` and `bandwidth-weights` from consensus.
2. Weighted pick; never reuse a relay in the same path; reject same /16 (when the sim has enough IPs — may need extra fake relays or extra compose relays).
3. Guard sticky: remember chosen guard on `Client`, reuse until it fails.
4. If the sim still has 3 relays on one /16, tests should document that /16 is waived below N relays, **or** advertise distinct /16s in the sim. Prefer distinct advertise IPs if easy.

**Tests:** 3-hop unique nicknames; guard reused across two `PickPath(3)`; weights bias (give one relay huge `w` and show it is chosen more often in a loop).

**Out of scope:** vanguards, restricted cones, family exclusion (unless family lines already exist).

---

### Stream isolation

- [ ] **Stream isolation** — SOCKS isolation flags → separate circuits

**Spec:** Tor SOCKS isolation (`IsolateSOCKSAuth`, `IsolateDestAddr`, `IsolateDestPort`, `IsolateClientAddr`). Different isolation keys ⇒ different circuits. Same key may share.

**Now:** `cmd/gotor` builds one 3-hop circuit and hands it to SOCKS. All streams share it.

**Do:**

1. Isolation key: at least SOCKS username/password; optionally dest host:port.
2. Circuit pool: lookup/create by key; idle timeout optional (not required).
3. Default (no SOCKS auth, same dest policy): may keep sharing one circuit so existing SOCKS test still passes.

**Tests:** two SOCKS connections with different user/pass use different CircIDs (or different guard CircIDs); same user/pass can share; existing SOCKS e2e still works.

**Out of scope:** IsolateClientProtocol, session group IDs.

---

### DESTROY / TRUNCATE reasons

- [ ] **DESTROY / TRUNCATE reasons** — propagate and surface to SOCKS

**Spec:** [Tearing down circuits](https://spec.torproject.org/tor-spec/tearing-down-circuits.html). DESTROY body = 1-byte reason. TRUNCATE/TRUNCATED exist but are unused in modern Tor; implement DESTROY well first. Reasons include PROTOCOL, INTERNAL, REQUESTED, HIBERNATING, RESOURCELIMIT, CONNECTFAILED, OR_IDENTITY, CHANNEL_CLOSED, FINISHED, TIMEOUT, DESTROYED, NOSUCHSERVICE, …

**Now:** DESTROY exists. Reasons hardcoded (ntor fail 1, hop fail 2, extend fail 6, propagate 11). Client Close sends reason 0. SOCKS does not see circuit death as a distinct error. TRUNCATE ignored.

**Do:**

1. Named constants for DESTROY reasons.
2. Sim: use the matching reason (identity mismatch vs protocol vs channel closed).
3. Client: on DESTROY, fail in-flight streams/Dial with that reason; SOCKS replies general failure (0x01) or connection refused when it was an exit BEGIN fail (that is END, not DESTROY).
4. TRUNCATE: optional recognize-and-DESTROY-the-rest; not required if unused.

**Tests:** identity mismatch DESTROY reason is OR_IDENTITY (or whatever we map); closing SOCKS client sends REQUESTED; stream still gets END reasons as today.

**Out of scope:** TRUNCATE as a normal path-shortening feature.

---

### RELAY_BEGIN flags

- [ ] **RELAY_BEGIN flags** — IPv6 okay / IPv4 not okay / prefer IPv6

**Spec:** [opening streams](https://spec.torproject.org/tor-spec/opening-streams.html#opening). After `ADDRPORT\0`, 4-byte flags: bit0 IPv6 OK, bit1 IPv4 not OK, bit2 IPv6 preferred.

**Now:** `BeginPayload` allocates 4 flag bytes but leaves them zero. Sim `ParseBegin` uses host:port only; `net.Dial` IPv4 in practice (sim is IPv4).

**Do:**

1. Set flags from Dial options (default: IPv6 OK unset is fine for v4-only sim).
2. Parse flags on the exit; if IPv4 not OK and only IPv4 available, END with an appropriate reason.
3. Prefer IPv6 when both exist (unit-test with a stub resolver, not public DNS).

**Tests:** payload round-trip flags; exit honors IPv4-not-OK by refusing an IPv4-only dest.

**Out of scope:** real IPv6 compose network unless already easy.

---

## Onion services (v3, sim-only)

Do these in order. All sim-only. No public HSDirs. Client currently returns `ErrOnion`.

### HS keys

- [ ] **HS keys** — blinded ed25519, subcredential

**Spec:** [rend-spec hidden service identities](https://spec.torproject.org/rend-spec/protocol-overview.html#SUBCRED), blinded keys, time period. `blinded_key = ed25519_blind(identity_sk, nonce(period, replica))`. `credential = H("credential" | pubkey)`. `subcredential = H("subcredential" | credential | blinded_pubkey)`.

**Do:** generate identity keypair; compute blinded key for a fixed sim time period; subcredential. No network.

**Tests:** vectors if we adopt known test vectors; blinding is deterministic; public address is 56-char `.onion` (pubkey + checksum + version, base32).

---

### HS descriptor

- [ ] **HS descriptor** — build/parse/encrypt (first/second layer)

**Spec:** [HS descriptor](https://spec.torproject.org/rend-spec/hsdesc.html). Outer: blinded id, revision-counter, superencrypted blob. Inner layers: intro points, ntor onion-key, auth, lifetime. Encrypted to subcredential / descriptor cookie as specified.

**Depends on:** HS keys.

**Do:** build a descriptor with one intro point (sim relay); parse+decrypt back to the same intro ntor key and addr.

**Tests:** encrypt/decrypt round-trip; bit flip fails authenticate.

**Out of scope:** client auth (restricted discovery), multiple intro auth types beyond ntor.

---

### HSDir

- [ ] **HSDir** — store/fetch descriptors in the sim

**Spec:** [HSDir ring](https://spec.torproject.org/rend-spec/hsdesc-index.html). Index from blinded key + time period + replica. HTTP `POST` / `GET` `/tor/hs/3/<descriptor-id>`.

**Do:** sim directory (or relays with HSDir flag) stores by descriptor id. Service publishes. Client fetches. Time period frozen in sim.

**Tests:** publish then fetch equals. Unknown id 404.

---

### INTRO

- [ ] **INTRO** — ESTABLISH_INTRO / INTRODUCE1 / INTRODUCE2

**Spec:** [introduction protocol](https://spec.torproject.org/rend-spec/introduction-protocol.html). ESTABLISH_INTRO (service→IP) with MAC of the circuit keys. INTRO_ESTABLISHED. INTRODUCE1 (client→IP) encrypted to service. INTRODUCE2 (IP→service).

**Do:** sim intro-point relay handles ESTABLISH_INTRO. Client sends INTRODUCE1 on a 3-hop circuit to that relay. Service circuit receives INTRODUCE2 and decrypts rend cookie + client ntor.

**Tests:** establish + introduce delivers the cookie/ntor to the service. Bad MAC rejected.

---

### RENDEZVOUS

- [ ] **RENDEZVOUS** — ESTABLISH_RENDEZVOUS / RENDEZVOUS1 / RENDEZVOUS2

**Spec:** [rendezvous protocol](https://spec.torproject.org/rend-spec/rendezvous-protocol.html). Client ESTABLISH_RENDEZVOUS with 20-byte cookie. Service RENDEZVOUS1 to RP (cookie + ntor handshake). RP RENDEZVOUS2 to client. Then both share a 3-hop+3-hop joined circuit; onion hops include the ntor with extra data (hs_ntor).

**Do:** sim RP relay. hs_ntor handshake. After RENDEZVOUS2, RELAY cells from client reach the service and vice versa (BEGIN on the joined circuit).

**Tests:** join then send a DATA ping. Wrong cookie fails.

---

### Client .onion

- [ ] **Client .onion** — SOCKS to `*.onion` via intro+rend (drop `ErrOnion`)

**Depends on:** all HS items above.

**Do:** SOCKS domain `*.onion` (56-char v3): decode pubkey, fetch desc from HSDir, pick intro, build rend circuit, INTRODUCE1, wait RENDEZVOUS2, BEGIN to the service. Sim origin can be a gotor onion service that returns a known body.

**Tests:** SOCKS fetch `http://<v3>.onion/` returns the service body. Still reject garbage/v2 addresses.

**Out of scope:** onion v2, client authorization, introduction PoW.

---

## Hardening / interop

### C-Tor chutney

- [ ] **C-Tor chutney** — optional compose profile; gotor client vs real `tor` relays

**Do:** `docker compose --profile chutney` (or similar) runs official `tor` relays + dirauth. gotor client bootstraps from that DirPort and builds a circuit. Keep the default profile on the pure-Go sim.

**Tests:** one HTTP fetch through chutney. Must stay opt-in (image size, license, flakiness).

**Out of scope:** gotor as a relay on the public network; mixing chutney into `make test-unit`.

---

### Congestion control (prop 324)

- [ ] **Congestion control (prop 324)** — ntor-v3 CC extension, XON/XOFF

**Depends on:** ntor-v3 extra-data.

**Spec:** [prop 324](https://spec.torproject.org/proposals/324-rtt-congestion-control.html). ntor-v3 extra-data: version, sendme_inc, cc_alg. Relay cmds XOFF=43, XON=44. When CC is on, circuit SENDME windows are replaced (or sendme_inc changes).

**Do (minimum):** negotiate cc_alg=0 (off) safely; if we advertise Vegas, implement XON/XOFF enough that a stream pause/resume works in sim. Do not break SENDME v1 paths when CC is off.

**Tests:** handshake extra-data round-trip; default still SENDME v1; if Vegas on, XOFF then XON unblocks.

---

### Circuit padding (prop 254)

- [ ] **Circuit padding (prop 254)** — PADDING_NEGOTIATE relay msgs

**Spec:** [padding-spec circuit-level](https://spec.torproject.org/padding-spec/circuit-level-padding.html). RELAY_PADDING_NEGOTIATE (41) / NEGOTIATED (42). Machines for intro/rdv cover. Can start as: parse + reply “no padding”, still ignore RELAY_DROP.

**Do:** encode/decode negotiate; sim replies none; client does not crash. Optional: emit RELAY_DROP on a timer (weak).

**Tests:** negotiate round-trip; circuit still carries HTTP.

**Out of scope:** full state machines matching C-Tor.

---

### Conflux (prop 329)

- [ ] **Conflux (prop 329)** — later, if ever

Do not start unless asked. Multipath linked circuits, RTT switch, sequence numbers. No spec expansion needed until then.

---

## Housekeeping

### CI

- [ ] **CI** — GitHub Actions: `docker compose` unit + integration

**Do:** workflow on push/PR: `docker compose build test-unit && docker compose --profile unit run --rm --no-deps test-unit`. Optional second job: `make test` integration (needs compose network). No `go test` on the runner host.

**Tests:** the workflow itself going green.

---

### README

- [ ] **README** — keep the capability table in sync with this file

Update the status table when merging protocol PRs (CREATE_FAST, BEGIN_DIR, SENDME v1, onion, etc.). Do not claim C-Tor interop or public-network use.

---

## Working rules (for implementers)

- New branch from `main`, one checkbox, Docker tests, commit, `gh pr create`.
- Hold hop crypto seal+write on one mutex. Exit DATA toward origin must not block the cell read loop (per-stream write queue).
- Next protocol item: **ntor-v3**.
