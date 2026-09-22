package client

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/adam/gotor/directory"
)

func (c *Client) PickPath(n int) ([]*directory.Relay, error) {
	if n < 1 {
		n = 3
	}
	var guards, middles, exits, all []*directory.Relay
	all = c.Relays
	for _, r := range all {
		switch {
		case r.Has("Exit"):
			exits = append(exits, r)
		case r.Has("Guard"):
			guards = append(guards, r)
		default:
			middles = append(middles, r)
		}
	}
	if n == 1 {
		r := pickWeighted(all, nil)
		if r == nil {
			return nil, fmt.Errorf("no relays")
		}
		return []*directory.Relay{r}, nil
	}
	g := c.Guard
	if g == nil || !relayIn(all, g) {
		g = pickWeighted(guards, nil)
		if g == nil {
			g = pickWeighted(all, nil)
		}
		c.Guard = g
	}
	e := pickWeighted(exits, []*directory.Relay{g})
	if e == nil {
		e = pickWeighted(all, []*directory.Relay{g})
	}
	var m *directory.Relay
	if n >= 3 {
		m = pickWeighted(middles, []*directory.Relay{g, e})
		if m == nil {
			m = pickWeighted(all, []*directory.Relay{g, e})
		}
		if m == nil {
			m = g
		}
	}
	if g == nil || e == nil {
		return nil, fmt.Errorf("not enough relays for a %d-hop path", n)
	}
	if n == 2 {
		return []*directory.Relay{g, e}, nil
	}
	return []*directory.Relay{g, m, e}, nil
}

func (c *Client) PickPathTo(end *directory.Relay) ([]*directory.Relay, error) {
	if end == nil {
		return nil, fmt.Errorf("no end relay")
	}
	g := c.Guard
	if g == nil || g == end {
		g = pickWeighted(c.Relays, []*directory.Relay{end})
		if g != nil {
			c.Guard = g
		}
	}
	if g == nil {
		return []*directory.Relay{end}, nil
	}
	m := pickWeighted(c.Relays, []*directory.Relay{g, end})
	if m == nil {
		return []*directory.Relay{g, end}, nil
	}
	return []*directory.Relay{g, m, end}, nil
}

func relayIn(pool []*directory.Relay, want *directory.Relay) bool {
	for _, r := range pool {
		if r == want {
			return true
		}
	}
	return false
}

func same16(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	return a4[0] == b4[0] && a4[1] == b4[1]
}

func pickWeighted(pool []*directory.Relay, used []*directory.Relay) *directory.Relay {
	var cand []*directory.Relay
	for _, r := range pool {
		if relayIn(used, r) {
			continue
		}
		cand = append(cand, r)
	}
	if len(cand) == 0 {
		return nil
	}
	var distinct []*directory.Relay
	for _, r := range cand {
		clash := false
		for _, u := range used {
			if same16(r.Address, u.Address) {
				clash = true
				break
			}
		}
		if !clash {
			distinct = append(distinct, r)
		}
	}
	if len(distinct) > 0 {
		cand = distinct
	}
	total := 0
	for _, r := range cand {
		w := r.Bandwidth
		if w < 1 {
			w = 1
		}
		total += w
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(total)))
	if err != nil {
		return cand[0]
	}
	x := n.Int64()
	for _, r := range cand {
		w := r.Bandwidth
		if w < 1 {
			w = 1
		}
		x -= int64(w)
		if x < 0 {
			return r
		}
	}
	return cand[len(cand)-1]
}
