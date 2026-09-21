package sim

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adam/gotor/directory"
)

func (n *Network) serveDir(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/tor/status-vote/current/consensus":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(n.consensusDoc()))
	case "/tor/server/all":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(n.descriptorsDoc()))
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
		if has(k.Flags, "Exit") {
			fmt.Fprintf(&b, "accept *:*\n")
		} else {
			fmt.Fprintf(&b, "reject *:*\n")
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func has(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}
