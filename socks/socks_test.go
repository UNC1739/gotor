package socks

import (
	"io"
	"net"
	"testing"
	"time"
)

func socksConnect(t *testing.T, atyp byte, addr []byte, port uint16) (gotHost string, gotPort uint16, status byte) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		done <- Handle(server, func(host string, port uint16) (io.ReadWriteCloser, error) {
			gotHost = host
			gotPort = port
			a, b := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, a)
				_ = a.Close()
			}()
			return b, nil
		})
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, 1, 0, atyp}
	req = append(req, addr...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	status = hdr[1]
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return gotHost, gotPort, status
}

func TestHandleDomainConnect(t *testing.T) {
	addr := append([]byte{byte(len("example.com"))}, []byte("example.com")...)
	host, port, status := socksConnect(t, 3, addr, 80)
	if status != 0 || host != "example.com" || port != 80 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}

func TestHandleIPv4(t *testing.T) {
	host, port, status := socksConnect(t, 1, []byte{1, 2, 3, 4}, 443)
	if status != 0 || host != "1.2.3.4" || port != 443 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}

func TestHandleRejectsSOCKS4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{4, 1})
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleUnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 2, 0, 1})
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 7 {
		t.Fatalf("status %d", hdr[1])
	}
}
