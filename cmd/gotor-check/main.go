package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	socksAddr := env("GOTOR_SOCKS", "127.0.0.1:9050")
	rawURL := env("GOTOR_CHECK_URL", "http://origin:8080/")
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		body, err := fetch(socksAddr, rawURL)
		if err == nil && strings.Contains(string(body), "gotor-origin-ok") {
			fmt.Printf("ok: fetched %q through %s\n", rawURL, socksAddr)
			os.Exit(0)
		}
		last = err
		if err == nil {
			last = fmt.Errorf("unexpected body %q", body)
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Fprintf(os.Stderr, "check failed: %v\n", last)
	os.Exit(1)
}

func fetch(socksAddr, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return nil, err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return nil, fmt.Errorf("socks auth rejected")
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	var p [2]byte
	var pi int
	fmt.Sscanf(port, "%d", &pi)
	binary.BigEndian.PutUint16(p[:], uint16(pi))
	req = append(req, p[:]...)
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	if hdr[1] != 0 {
		return nil, fmt.Errorf("socks connect status %d", hdr[1])
	}
	switch hdr[3] {
	case 1:
		_, _ = io.ReadFull(c, make([]byte, 4+2))
	case 4:
		_, _ = io.ReadFull(c, make([]byte, 16+2))
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return nil, err
		}
		_, _ = io.ReadFull(c, make([]byte, int(n[0])+2))
	}
	httpReq := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", u.RequestURI(), u.Host)
	if _, err := io.WriteString(c, httpReq); err != nil {
		return nil, err
	}
	return io.ReadAll(c)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
