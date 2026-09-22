package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/adam/gotor/crypto"
)

func TestResponsibleHSDirs(t *testing.T) {
	var hsdirs []*Relay
	for i := 0; i < 8; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r := &Relay{
			Nickname:  string(rune('a' + i)),
			Ed25519ID: pub,
			Flags:     map[string]bool{"HSDir": true},
		}
		r.Identity[0] = byte(i + 1)
		hsdirs = append(hsdirs, r)
	}
	blinded, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := crypto.DisasterSRV(crypto.HSPeriodLength, 100)
	got := ResponsibleHSDirs(hsdirs, blinded, srv, 100, crypto.HSSpreadFetch)
	if len(got) != 6 {
		t.Fatalf("got %d want 6", len(got))
	}
	seen := map[[20]byte]bool{}
	for _, r := range got {
		if seen[r.Identity] {
			t.Fatal("duplicate")
		}
		seen[r.Identity] = true
	}
	other := ResponsibleHSDirs(hsdirs, blinded, srv, 101, crypto.HSSpreadFetch)
	same := 0
	for i := range got {
		if got[i].Identity == other[i].Identity {
			same++
		}
	}
	if same == len(got) {
		t.Fatal("period did not rotate ring")
	}
}
