package client

import (
	"testing"

	"github.com/adam/gotor/directory"
)

func TestPickPathRoles(t *testing.T) {
	g := &directory.Relay{Nickname: "g", Flags: map[string]bool{"Guard": true}}
	m := &directory.Relay{Nickname: "m", Flags: map[string]bool{}}
	e := &directory.Relay{Nickname: "e", Flags: map[string]bool{"Exit": true}}
	c := &Client{Relays: []*directory.Relay{g, m, e}}
	p, err := c.PickPath(0)
	if err != nil || len(p) != 3 || p[0] != g || p[1] != m || p[2] != e {
		t.Fatalf("3-hop default %+v %v", nicks(p), err)
	}
	p2, err := c.PickPath(2)
	if err != nil || len(p2) != 2 || p2[0] != g || p2[1] != e {
		t.Fatalf("2-hop %+v %v", nicks(p2), err)
	}
	p1, err := c.PickPath(1)
	if err != nil || len(p1) != 1 {
		t.Fatalf("1-hop %+v %v", nicks(p1), err)
	}

}

func TestPickPathFourHopCapsAtThree(t *testing.T) {
	g := &directory.Relay{Nickname: "g", Flags: map[string]bool{"Guard": true}}
	m := &directory.Relay{Nickname: "m", Flags: map[string]bool{}}
	e := &directory.Relay{Nickname: "e", Flags: map[string]bool{"Exit": true}}
	c := &Client{Relays: []*directory.Relay{g, m, e}}
	p, err := c.PickPath(4)
	if err != nil || len(p) != 3 || p[0] != g || p[1] != m || p[2] != e {
		t.Fatalf("%+v %v", nicks(p), err)
	}
}


func TestPickPathNoRelays(t *testing.T) {
	c := &Client{}
	if _, err := c.PickPath(1); err == nil {
		t.Fatal("expected no relays")
	}
	if _, err := c.PickPath(3); err == nil {
		t.Fatal("expected not enough")
	}
}

func TestPickPathNoGuardUsesAll(t *testing.T) {
	e := &directory.Relay{Nickname: "e", Flags: map[string]bool{"Exit": true}}
	o := &directory.Relay{Nickname: "o", Flags: map[string]bool{}}
	c := &Client{Relays: []*directory.Relay{e, o}}
	p, err := c.PickPath(3)
	if err != nil || len(p) != 3 {
		t.Fatalf("%+v %v", nicks(p), err)
	}
}

func TestPickPathMiddleFromExtraGuard(t *testing.T) {
	g := &directory.Relay{Nickname: "g", Flags: map[string]bool{"Guard": true}}
	g2 := &directory.Relay{Nickname: "g2", Flags: map[string]bool{"Guard": true}}
	e := &directory.Relay{Nickname: "e", Flags: map[string]bool{"Exit": true}}
	c := &Client{Relays: []*directory.Relay{g, g2, e}}
	p, err := c.PickPath(3)
	if err != nil || len(p) != 3 || p[2] != e {
		t.Fatalf("%+v %v", nicks(p), err)
	}
}


func TestBuildCircuitEmpty(t *testing.T) {
	c := &Client{}
	if _, err := c.BuildCircuit(nil); err == nil {
		t.Fatal("expected empty path")
	}
}

func TestDialOnionCaseInsensitive(t *testing.T) {
	circ := &Circuit{}
	if _, err := circ.Dial("Example.ONION", 80); err != ErrOnion {
		t.Fatalf("%v", err)
	}
}


func nicks(p []*directory.Relay) []string {
	var s []string
	for _, r := range p {
		s = append(s, r.Nickname)
	}
	return s
}
