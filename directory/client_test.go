package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPGetOK(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nnetwork-status-version 3\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := HTTPGet(client, "/tor/status-vote/current/consensus")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "network-status-version 3") {
		t.Fatalf("%q", got)
	}
}

func TestHTTPGetNotFound(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 404 Not Found\r\n\r\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := HTTPGet(client, "/tor/missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchUsableRelays(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ntor[0] = 2
	ed := make([]byte, 32)
	ed[0] = 3
	var id [20]byte
	copy(id[:], ident)
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n" +
		"directory-footer\n"
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignConsensus(cons, key)
	if err != nil {
		t.Fatal(err)
	}
	desc := "router gotor1 10.0.0.2 9001 0 0\nfingerprint " + FingerprintHex(id) +
		"\nntor-onion-key " + B64(ntor) + "\nmaster-key-ed25519 " + B64(ed) + "\naccept *:*\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/keys/authority", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(EncodeAuthorityKey(&key.PublicKey))
	})
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, signed)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, desc)
	})

	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	relays, err := Fetch(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 || relays[0].Nickname != "gotor1" || relays[0].NTorOnionKey[0] != 2 {
		t.Fatalf("%+v", relays)
	}
}

func TestFetchNoUsableRelays(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Running Valid\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cons)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "router gotor1 10.0.0.2 9001 0 0\n")
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected no usable relays")
	}
}

func TestFetchRW(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 9
	cons := "network-status-version 3\n" +
		"r gotor9 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.9 9001 0\n" +
		"s Guard Running Valid Fast\n"
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 1024)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 200 OK\r\n\r\n"+cons)
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	relays, err := FetchRW(client)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 || relays[0].Nickname != "gotor9" {
		t.Fatalf("%+v", relays)
	}
}

func TestHTTPGetTruncatedHeaders(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := HTTPGet(client, "/tor/status-vote/current/consensus"); err == nil {
		t.Fatal("expected truncated headers")
	}
}

func TestFetchConsensusNotFound(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected fetch error")
	}
}

func TestFetchRWBadConsensus(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 200 OK\r\n\r\nr nick only\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := FetchRW(client); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFetchDescriptorsNotFound(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cons)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected descriptor 404")
	}
}

func TestHTTPGetWriteError(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close()
	_ = client.Close()
	if _, err := HTTPGet(client, "/tor/status-vote/current/consensus"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestFetchRWNotFound(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = io.WriteString(server, "HTTP/1.0 404 Not Found\r\n\r\n")
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := FetchRW(client); err == nil {
		t.Fatal("expected 404")
	}
}

func TestFetchBadConsensus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "r nick only\n")
	}))
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected consensus parse error")
	}
}

func TestFetchBadDescriptors(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cons)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "router gotor1 10.0.0.2 9001 0 0\nntor-onion-key "+B64(make([]byte, 20))+"\n")
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected descriptor parse error")
	}
}

func TestFetchSkipsZeroORPort(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 0 0\n" +
		"s Guard Running Valid Fast\n"
	ntor := make([]byte, 32)
	ntor[0] = 2
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cons)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "router gotor1 10.0.0.2 0 0 0\nntor-onion-key "+B64(ntor)+"\n")
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected no usable relays")
	}
}

func TestFetchSkipsNilAddress(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 not-an-ip 9001 0\n" +
		"s Guard Running Valid Fast\n"
	ntor := make([]byte, 32)
	ntor[0] = 2
	mux := http.NewServeMux()
	mux.HandleFunc("/tor/status-vote/current/consensus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, cons)
	})
	mux.HandleFunc("/tor/server/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "router gotor1 10.0.0.2 9001 0 0\nntor-onion-key "+B64(ntor)+"\n")
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Fetch(u.Host); err == nil {
		t.Fatal("expected no usable relays")
	}
}

func TestFetchUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := Fetch(addr); err == nil {
		t.Fatal("expected unreachable")
	}
}

func TestHTTPGetPeerClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := HTTPGet(client, "/tor/status-vote/current/consensus"); err == nil {
		t.Fatal("expected peer close")
	}
}
