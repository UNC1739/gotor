package directory

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func Fetch(dirAddr string) ([]*Relay, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	cons, err := get(c, "http://"+dirAddr+"/tor/status-vote/current/consensus")
	if err != nil {
		return nil, fmt.Errorf("consensus: %w", err)
	}
	relays, err := ParseConsensus(cons)
	if err != nil {
		return nil, err
	}
	desc, err := get(c, "http://"+dirAddr+"/tor/server/all")
	if err != nil {
		return nil, fmt.Errorf("descriptors: %w", err)
	}
	if err := ParseDescriptors(desc, relays); err != nil {
		return nil, err
	}
	var out []*Relay
	for _, r := range relays {
		if r.ORPort == 0 || r.Address == nil {
			continue
		}
		var zero [32]byte
		if r.NTorOnionKey == zero {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable relays in directory")
	}
	return out, nil
}

func get(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
