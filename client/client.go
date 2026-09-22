package client

import (
	"fmt"
	"log/slog"

	"github.com/adam/gotor/directory"
)

type Client struct {
	DirAddr string
	Relays  []*directory.Relay
	Log     *slog.Logger
}

func Bootstrap(dirAddr string) (*Client, error) {
	relays, err := directory.Fetch(dirAddr)
	if err != nil {
		return nil, err
	}
	return &Client{DirAddr: dirAddr, Relays: relays, Log: slog.Default()}, nil
}

func BootstrapMicro(dirAddr string) (*Client, error) {
	relays, err := directory.FetchMicro(dirAddr)
	if err != nil {
		return nil, err
	}
	return &Client{DirAddr: dirAddr, Relays: relays, Log: slog.Default()}, nil
}

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
	pick := func(pool []*directory.Relay) *directory.Relay {
		if len(pool) == 0 {
			return nil
		}
		return pool[0]
	}
	if n == 1 {
		if r := pick(all); r != nil {
			return []*directory.Relay{r}, nil
		}
		return nil, fmt.Errorf("no relays")
	}
	g := pick(guards)
	if g == nil {
		g = pick(all)
	}
	e := pick(exits)
	if e == nil {
		e = pick(all)
	}
	m := pick(middles)
	if m == nil {
		for _, r := range all {
			if r != g && r != e {
				m = r
				break
			}
		}
	}
	if m == nil {
		m = g
	}
	if g == nil || e == nil {
		return nil, fmt.Errorf("not enough relays for a %d-hop path", n)
	}
	if n == 2 {
		return []*directory.Relay{g, e}, nil
	}
	return []*directory.Relay{g, m, e}, nil
}
