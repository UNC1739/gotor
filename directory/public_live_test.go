//go:build publicnet

package directory

import "testing"

func TestFetchPublicLive(t *testing.T) {
	relays, err := FetchPublic()
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) < 3 {
		t.Fatalf("usable relays %d", len(relays))
	}
	var guards, exits int
	for _, r := range relays {
		if r.Has("Guard") {
			guards++
		}
		if r.Has("Exit") || r.ExitAccept {
			exits++
		}
	}
	if guards == 0 || exits == 0 {
		t.Fatalf("guards=%d exits=%d total=%d", guards, exits, len(relays))
	}
	t.Logf("public bootstrap: %d usable relays guards=%d exits=%d", len(relays), guards, exits)
}
