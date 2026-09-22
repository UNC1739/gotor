package client

import (
	"log/slog"
	"sync"

	"github.com/adam/gotor/directory"
)

type Client struct {
	DirAddr string
	Relays  []*directory.Relay
	Guard   *directory.Relay
	Hops    int
	NoFast  bool
	Log     *slog.Logger

	mu    sync.Mutex
	circs map[string]*Circuit
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

func BootstrapPublic() (*Client, error) {
	relays, err := directory.FetchPublic()
	if err != nil {
		return nil, err
	}
	return &Client{DirAddr: "public", Relays: relays, Log: slog.Default()}, nil
}


func (c *Client) CircuitFor(user, pass string) (*Circuit, error) {
	key := user + "\x00" + pass
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.circs == nil {
		c.circs = map[string]*Circuit{}
	}
	if circ, ok := c.circs[key]; ok {
		return circ, nil
	}
	hops := c.Hops
	if hops < 1 {
		hops = 3
	}
	path, err := c.PickPath(hops)
	if err != nil {
		return nil, err
	}
	if c.Log != nil {
		nicks := make([]string, 0, len(path))
		for _, r := range path {
			nicks = append(nicks, r.Nickname)
		}
		c.Log.Info("building circuit", "hops", len(path), "path", nicks)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		return nil, err
	}
	c.circs[key] = circ
	return circ, nil

}
