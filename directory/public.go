package directory

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	publicTimeout   = 180 * time.Second
	microBatch      = 96
	maxGuardsMicros = 48
	maxExitsMicros  = 48
	maxOtherMicros  = 48
)

type Snapshot struct {
	Relays     []*Relay
	All        []*Relay
	SRV        []byte
	PrevSRV    []byte
	ValidAfter time.Time
	HTTPAddr   string
}

func FetchPublic() ([]*Relay, error) {
	snap, err := FetchPublicSnapshotFrom(V3Authorities, "")
	if err != nil {
		return nil, err
	}
	return snap.Relays, nil
}

func FetchPublicSnapshot() (*Snapshot, error) {
	return FetchPublicSnapshotFrom(V3Authorities, "")
}

// FetchPublicFrom bootstraps from the given authorities. If dirAddr is set,
// every HTTP fetch uses that host (tests). Otherwise each authority's DirAddr.
func FetchPublicFrom(auths []Authority, dirAddr string) ([]*Relay, error) {
	snap, err := FetchPublicSnapshotFrom(auths, dirAddr)
	if err != nil {
		return nil, err
	}
	return snap.Relays, nil
}

func FetchPublicSnapshotFrom(auths []Authority, dirAddr string) (*Snapshot, error) {
	if len(auths) == 0 {
		return nil, fmt.Errorf("no directory authorities")
	}
	c := &http.Client{Timeout: publicTimeout}
	var last error
	seen := map[string]bool{}
	for _, a := range auths {
		addr := dirAddr
		if addr == "" {
			addr = a.DirAddr
		}
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		snap, err := fetchPublicOne(c, addr, auths)
		if err == nil {
			return snap, nil
		}
		last = fmt.Errorf("%s: %w", a.Nickname, err)
	}
	if last == nil {
		last = fmt.Errorf("no directory authority tried")
	}
	return nil, last
}

func fetchPublicOne(c *http.Client, dirAddr string, auths []Authority) (*Snapshot, error) {
	keyDoc, err := getPublic(c, dirAddr, "/tor/keys/all")
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	certs, err := ParseDirKeyCerts(keyDoc)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	want := map[string]Authority{}
	for _, a := range auths {
		want[strings.ToUpper(a.V3Ident)] = a
	}
	signing := map[string]*rsa.PublicKey{}
	now := time.Now()
	for _, cert := range certs {
		if _, ok := want[cert.Fingerprint]; !ok {
			continue
		}
		if err := cert.ValidAt(now); err != nil {
			continue
		}
		signing[cert.Fingerprint] = cert.Signing
	}
	if len(signing) < Quorum(len(auths)) {
		return nil, fmt.Errorf("keys: %d usable authority certs, need %d", len(signing), Quorum(len(auths)))
	}
	cons, err := getPublic(c, dirAddr, "/tor/status-vote/current/consensus-microdesc")
	if err != nil {
		return nil, fmt.Errorf("consensus: %w", err)
	}
	if !strings.Contains(cons, "network-status-version") {
		preview := cons
		if len(preview) > 80 {
			preview = preview[:80]
		}
		return nil, fmt.Errorf("consensus: not a network-status (%q)", preview)
	}
	if err := VerifyConsensusQuorum(cons, signing, len(auths)); err != nil {
		return nil, fmt.Errorf("consensus: %w", err)
	}
	relays, err := ParseConsensus(cons)
	if err != nil {
		return nil, err
	}
	hdr := ParseConsensusHeader(cons)
	selected := selectForMicros(relays)
	if err := fetchMicros(c, dirAddr, selected); err != nil {
		return nil, err
	}
	usable, err := usableRelays(selected)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Relays:     usable,
		All:        relays,
		SRV:        hdr.SRV,
		PrevSRV:    hdr.PrevSRV,
		ValidAfter: hdr.ValidAfter,
		HTTPAddr:   dirAddr,
	}, nil
}

func selectForMicros(relays []*Relay) []*Relay {
	var guards, exits, other []*Relay
	for _, r := range relays {
		if !r.Has("Running") || !r.Has("Valid") || len(r.MicroHash) != 32 {
			continue
		}
		if r.Has("BadExit") {
			continue
		}
		switch {
		case r.Has("Guard"):
			guards = append(guards, r)
		case r.Has("Exit"):
			exits = append(exits, r)
		default:
			other = append(other, r)
		}
	}
	trim := func(s []*Relay, n int) []*Relay {
		if len(s) > n {
			return s[:n]
		}
		return s
	}
	out := append([]*Relay{}, trim(guards, maxGuardsMicros)...)
	out = append(out, trim(exits, maxExitsMicros)...)
	out = append(out, trim(other, maxOtherMicros)...)
	return out
}

func FetchMicros(dirAddr string, relays []*Relay) error {
	c := &http.Client{Timeout: publicTimeout}
	return fetchMicros(c, dirAddr, relays)
}

func fetchMicros(c *http.Client, dirAddr string, relays []*Relay) error {
	var hashes []string
	var batch []*Relay
	for _, r := range relays {
		if len(r.MicroHash) != 32 {
			continue
		}
		var zero [32]byte
		if len(r.Ed25519ID) == 32 && r.NTorOnionKey != zero {
			continue
		}
		hashes = append(hashes, strings.TrimRight(base64.StdEncoding.EncodeToString(r.MicroHash), "="))
		batch = append(batch, r)
	}
	if len(hashes) == 0 {
		return nil
	}
	type span struct{ i, j int }
	var spans []span
	for i := 0; i < len(hashes); i += microBatch {
		j := i + microBatch
		if j > len(hashes) {
			j = len(hashes)
		}
		spans = append(spans, span{i, j})
	}
	workers := 8
	if workers > len(spans) {
		workers = len(spans)
	}
	jobs := make(chan span)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var last error
	ok := 0
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				body, err := getPublic(c, dirAddr, "/tor/micro/d/"+strings.Join(hashes[s.i:s.j], "-"))
				if err != nil {
					mu.Lock()
					last = err
					mu.Unlock()
					continue
				}
				if err := ParseMicrodescriptors(body, batch[s.i:s.j]); err != nil {
					mu.Lock()
					last = err
					mu.Unlock()
					continue
				}
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	for _, s := range spans {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	if ok == 0 {
		if last == nil {
			last = fmt.Errorf("microdescriptors: empty")
		}
		return fmt.Errorf("microdescriptors: %w", last)
	}
	return nil
}

func getPublic(c *http.Client, dirAddr, path string) (string, error) {
	url := "http://" + dirAddr + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "gotor/0")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type dirSig struct {
	alg, ident, skdigest string
	sig                  []byte
	prefixes             []string
}

func parseDirectorySignatures(doc string) ([]dirSig, error) {
	const kw = "directory-signature "
	j := strings.Index(doc, "network-status-version")
	if j < 0 {
		return nil, fmt.Errorf("missing network-status-version")
	}
	first := strings.Index(doc[j:], "\n"+kw)
	firstAbs := -1
	if first >= 0 {
		firstAbs = j + first + 1
	} else if strings.HasPrefix(doc[j:], kw) {
		firstAbs = j
	} else {
		return nil, fmt.Errorf("missing directory-signature")
	}
	common := doc[j:firstAbs]
	var out []dirSig
	rest := doc
	off := 0
	for {
		i := strings.Index(rest, "\n"+kw)
		start := 0
		if i >= 0 {
			start = i + 1
		} else if off == 0 && strings.HasPrefix(rest, kw) {
			start = 0
		} else {
			break
		}
		abs := off + start
		nl := strings.Index(doc[abs:], "\n")
		if nl < 0 {
			return nil, fmt.Errorf("truncated directory-signature")
		}
		line := doc[abs : abs+nl]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("short directory-signature")
		}
		s := dirSig{alg: "sha1"}
		if len(fields) >= 4 {
			s.alg = fields[1]
			s.ident = strings.ToUpper(fields[2])
			s.skdigest = strings.ToUpper(fields[3])
		} else {
			s.ident = strings.ToUpper(fields[1])
			s.skdigest = strings.ToUpper(fields[2])
		}
		beginRel := strings.Index(doc[abs+nl:], "-----BEGIN SIGNATURE-----")
		endRel := strings.Index(doc[abs+nl:], "-----END SIGNATURE-----")
		if beginRel < 0 || endRel < 0 || endRel <= beginRel {
			return nil, fmt.Errorf("missing SIGNATURE object")
		}
		blob := doc[abs+nl+beginRel+len("-----BEGIN SIGNATURE-----") : abs+nl+endRel]
		raw, err := decodeB64Blob(blob)
		if err != nil {
			return nil, fmt.Errorf("signature base64: %w", err)
		}
		s.sig = raw
		s.prefixes = []string{
			common + "directory-signature ",
			doc[j:abs+nl] + " ",
			doc[j : abs+nl+1],
			common + line + " ",
			common + line + "\n",
		}
		out = append(out, s)
		next := abs + nl + endRel + len("-----END SIGNATURE-----")
		if next >= len(doc) {
			break
		}
		rest = doc[next:]
		off = next
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("missing directory-signature")
	}
	return out, nil
}

func VerifyConsensusQuorum(doc string, signing map[string]*rsa.PublicKey, nAuth int) error {
	sigs, err := parseDirectorySignatures(doc)
	if err != nil {
		return err
	}
	ok := 0
	seen := map[string]bool{}
	for _, s := range sigs {
		pub := signing[s.ident]
		if pub == nil || seen[s.ident] {
			continue
		}
		if s.skdigest != "" && rsaSHA1Hex(pub) != s.skdigest {
			continue
		}
		if !verifyDirSig(s, pub) {
			continue
		}
		seen[s.ident] = true
		ok++
	}
	need := Quorum(nAuth)
	if ok < need {
		return fmt.Errorf("directory-signature quorum %d/%d (need %d)", ok, nAuth, need)
	}
	return nil
}

func verifyDirSig(s dirSig, pub *rsa.PublicKey) bool {
	digest := func(p string) []byte {
		switch s.alg {
		case "", "sha1":
			h := sha1.Sum([]byte(p))
			return h[:]
		case "sha256":
			h := sha256.Sum256([]byte(p))
			return h[:]
		default:
			return nil
		}
	}
	for _, p := range s.prefixes {
		d := digest(p)
		if d == nil {
			return false
		}
		if rsa.VerifyPKCS1v15(pub, 0, d, s.sig) == nil {
			return true
		}
	}
	return false
}
