package sim

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adam/gotor/directory"
)

func (n *Network) serveDir(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.URL.Path == "/tor/status-vote/current/consensus":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(n.consensusDoc()))
	case req.URL.Path == "/tor/status-vote/current/consensus-microdesc":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(n.microConsensusDoc()))
	case req.URL.Path == "/tor/server/all":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(n.descriptorsDoc()))
	case strings.HasPrefix(req.URL.Path, "/tor/micro/d/"):
		n.serveMicro(w, strings.TrimPrefix(req.URL.Path, "/tor/micro/d/"))
	default:
		http.NotFound(w, req)
	}
}

func (n *Network) consensusDoc() string {
	var b strings.Builder
	now := time.Now().UTC()
	fmt.Fprintf(&b, "network-status-version 3\n")
	fmt.Fprintf(&b, "vote-status consensus\n")
	fmt.Fprintf(&b, "consensus-method 32\n")
	fmt.Fprintf(&b, "valid-after %s\n", now.Add(-time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "fresh-until %s\n", now.Add(24*time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "valid-until %s\n", now.Add(48*time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "known-flags Authority Exit Fast Guard HSDir Running Stable V2Dir Valid\n")
	dummy := make([]byte, 20)
	for _, r := range n.relays {
		k := r.Keys
		fmt.Fprintf(&b, "r %s %s %s %s %s %s %d %d\n",
			k.Nickname,
			directory.B64(k.Identity[:]),
			directory.B64(dummy),
			now.Format("2006-01-02"),
			now.Format("15:04:05"),
			k.AdvertiseIP.String(),
			k.ORPort,
			0,
		)
		fmt.Fprintf(&b, "s %s Running Stable Valid Fast\n", strings.Join(k.Flags, " "))
		fmt.Fprintf(&b, "pr Relay=1-4\n")
		if has(k.Flags, "Exit") {
			fmt.Fprintf(&b, "p accept 1-65535\n")
		} else {
			fmt.Fprintf(&b, "p reject 1-65535\n")
		}
	}
	fmt.Fprintf(&b, "directory-footer\n")
	return b.String()
}

func (n *Network) descriptorsDoc() string {
	var b strings.Builder
	for _, r := range n.relays {
		k := r.Keys
		fmt.Fprintf(&b, "router %s %s %d 0 0\n", k.Nickname, k.AdvertiseIP.String(), k.ORPort)
		fmt.Fprintf(&b, "fingerprint %s\n", directory.FingerprintHex(k.Identity))
		fmt.Fprintf(&b, "ntor-onion-key %s\n", directory.B64(k.NTor.Public[:]))
		fmt.Fprintf(&b, "master-key-ed25519 %s\n", directory.B64(k.EdIDPub))
		fmt.Fprintf(&b, "proto Relay=1-4\n")
		if has(k.Flags, "Exit") {
			fmt.Fprintf(&b, "accept *:*\n")
		} else {
			fmt.Fprintf(&b, "reject *:*\n")
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (n *Network) microdesc(k *RelayKeys) (string, [32]byte) {
	var b strings.Builder
	fmt.Fprintf(&b, "onion-key\n")
	fmt.Fprintf(&b, "ntor-onion-key %s\n", directory.B64(k.NTor.Public[:]))
	fmt.Fprintf(&b, "id ed25519 %s\n", directory.B64(k.EdIDPub))
	if has(k.Flags, "Exit") {
		fmt.Fprintf(&b, "p accept 1-65535\n")
	} else {
		fmt.Fprintf(&b, "p reject 1-65535\n")
	}
	s := b.String()
	return s, sha256.Sum256([]byte(s))
}

func (n *Network) microConsensusDoc() string {
	var b strings.Builder
	now := time.Now().UTC()
	fmt.Fprintf(&b, "network-status-version 3 microdesc\n")
	fmt.Fprintf(&b, "vote-status consensus\n")
	fmt.Fprintf(&b, "consensus-method 32\n")
	fmt.Fprintf(&b, "valid-after %s\n", now.Add(-time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "fresh-until %s\n", now.Add(24*time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "valid-until %s\n", now.Add(48*time.Hour).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "known-flags Authority Exit Fast Guard HSDir Running Stable V2Dir Valid\n")
	for _, r := range n.relays {
		k := r.Keys
		_, sum := n.microdesc(k)
		fmt.Fprintf(&b, "r %s %s %s %s %s %d %d\n",
			k.Nickname,
			directory.B64(k.Identity[:]),
			now.Format("2006-01-02"),
			now.Format("15:04:05"),
			k.AdvertiseIP.String(),
			k.ORPort,
			0,
		)
		fmt.Fprintf(&b, "s %s Running Stable Valid Fast\n", strings.Join(k.Flags, " "))
		fmt.Fprintf(&b, "m %s\n", directory.B64(sum[:]))
		fmt.Fprintf(&b, "pr Relay=1-4\n")
		if has(k.Flags, "Exit") {
			fmt.Fprintf(&b, "p accept 1-65535\n")
		} else {
			fmt.Fprintf(&b, "p reject 1-65535\n")
		}
	}
	fmt.Fprintf(&b, "directory-footer\n")
	return b.String()
}

func (n *Network) serveMicro(w http.ResponseWriter, spec string) {
	want := map[string]struct{}{}
	for _, h := range strings.Split(spec, "-") {
		if h != "" {
			want[h] = struct{}{}
		}
	}
	var b strings.Builder
	for _, r := range n.relays {
		body, sum := n.microdesc(r.Keys)
		if _, ok := want[directory.B64(sum[:])]; ok {
			b.WriteString(body)
		}
	}
	if b.Len() == 0 {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(b.String()))
}

func has(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}
