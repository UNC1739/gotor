package directory

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	return usableRelays(relays)
}

func FetchMicro(dirAddr string) ([]*Relay, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	cons, err := get(c, "http://"+dirAddr+"/tor/status-vote/current/consensus-microdesc")
	if err != nil {
		return nil, fmt.Errorf("micro consensus: %w", err)
	}
	relays, err := ParseConsensus(cons)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, r := range relays {
		if len(r.MicroHash) == 32 {
			hashes = append(hashes, B64(r.MicroHash))
		}
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("no microdescriptor hashes")
	}
	body, err := get(c, "http://"+dirAddr+"/tor/micro/d/"+strings.Join(hashes, "-"))
	if err != nil {
		return nil, fmt.Errorf("microdescriptors: %w", err)
	}
	if err := ParseMicrodescriptors(body, relays); err != nil {
		return nil, err
	}
	return usableRelays(relays)
}

func usableRelays(relays []*Relay) ([]*Relay, error) {
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

func FetchRW(rw io.ReadWriter) ([]*Relay, error) {
	cons, err := HTTPGet(rw, "/tor/status-vote/current/consensus")
	if err != nil {
		return nil, fmt.Errorf("consensus: %w", err)
	}
	relays, err := ParseConsensus(cons)
	if err != nil {
		return nil, err
	}
	return relays, nil
}

func HTTPGet(rw io.ReadWriter, path string) (string, error) {
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: directory\r\nConnection: close\r\n\r\n", path)
	if _, err := io.WriteString(rw, req); err != nil {
		return "", err
	}
	br := bufio.NewReader(rw)
	status, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.Contains(status, "200") {
		return "", fmt.Errorf("http: %s", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	b, err := io.ReadAll(br)
	if err != nil {
		return "", err
	}
	return string(b), nil
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
