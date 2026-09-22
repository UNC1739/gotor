package socks

import (
	"io"
	"net"
	"strings"
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
		done <- Handle(server, func(host string, port uint16, user, pass string) (io.ReadWriteCloser, error) {
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

func TestHandleMaxDomain(t *testing.T) {
	host := strings.Repeat("a", 255)
	addr := append([]byte{255}, []byte(host)...)
	got, port, status := socksConnect(t, 3, addr, 80)
	if status != 0 || got != host || port != 80 {
		t.Fatalf("hostlen=%d port=%d status=%d", len(got), port, status)
	}
}


func TestHandleIPv4(t *testing.T) {
	host, port, status := socksConnect(t, 1, []byte{1, 2, 3, 4}, 443)
	if status != 0 || host != "1.2.3.4" || port != 443 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}

func TestHandleIPv4Broadcast(t *testing.T) {
	host, port, status := socksConnect(t, 1, []byte{255, 255, 255, 255}, 80)
	if status != 0 || host != "255.255.255.255" || port != 80 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}


func TestHandleRejectsSOCKS4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
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
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
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

func TestHandleUDPAssociate(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 3, 0, 1})
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 7 {
		t.Fatalf("status %d", hdr[1])
	}
}

func TestHandleIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	if ip == nil {
		t.Fatal("parse")
	}
	host, port, status := socksConnect(t, 4, []byte(ip.To16()), 80)
	if status != 0 || host != "2001:db8::1" || port != 80 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}

func TestHandleIPv6MappedIPv4(t *testing.T) {
	ip := net.ParseIP("::ffff:1.2.3.4")
	host, port, status := socksConnect(t, 4, []byte(ip.To16()), 80)
	if status != 0 || port != 80 {
		t.Fatalf("host=%s port=%d status=%d", host, port, status)
	}
}


func TestHandleTruncatedGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5})
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleBadATYP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 1, 0, 2})
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleDialFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	errc := make(chan error, 1)
	go func() {
		errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) {
			return nil, io.ErrClosedPipe
		})
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 1 {
		t.Fatalf("status %d", hdr[1])
	}
}

func TestHostPort(t *testing.T) {
	if HostPort("example.com", 80) != "example.com:80" {
		t.Fatal(HostPort("example.com", 80))
	}
	if HostPort("127.0.0.1", 9050) != "127.0.0.1:9050" {
		t.Fatal(HostPort("127.0.0.1", 9050))
	}
}

func TestServeAcceptsConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = Serve(ln, func(string, uint16, string, string) (io.ReadWriteCloser, error) {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		})
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0 {
		t.Fatalf("status %d", hdr[1])
	}
}

func TestHandleTruncatedMethods(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 2})
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleTruncatedAddr(t *testing.T) {
	cases := [][]byte{
		{5, 1, 0, 1, 1, 2},
		{5, 1, 0, 4, 1, 2, 3, 4},
		{5, 1, 0, 3, 8, 'a', 'b'},
		{5, 1, 0, 1, 1, 2, 3, 4},
	}
	for _, req := range cases {
		client, server := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
		_, _ = client.Write([]byte{5, 1, 0})
		_, _ = io.ReadFull(client, make([]byte, 2))
		_, _ = client.Write(req)
		_ = client.Close()
		_ = server.Close()
		select {
		case err := <-errc:
			if err == nil {
				t.Fatalf("expected error for %x", req)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout %x", req)
		}
	}
}

func TestHandleEmptyDomain(t *testing.T) {
	host, port, status := socksConnect(t, 3, []byte{0}, 80)
	if status != 0 || host != "" || port != 80 {
		t.Fatalf("host=%q port=%d status=%d", host, port, status)
	}
}

func TestHandleBadAtyp(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 1, 0, 2})
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected bad atyp")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleNoMethodsThenConnect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	if _, err := client.Write([]byte{5, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(client, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 5 || rep[1] != 0xff {
		t.Fatalf("method %x", rep)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected no acceptable method")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}



func TestHandleUserPass(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	var gotUser, gotPass string
	done := make(chan error, 1)
	go func() {
		done <- Handle(server, func(host string, port uint16, user, pass string) (io.ReadWriteCloser, error) {
			gotUser, gotPass = user, pass
			a, b := net.Pipe()
			go func() {
				_, _ = io.Copy(io.Discard, a)
				_ = a.Close()
			}()
			return b, nil
		})
	}()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	meth := make([]byte, 2)
	if _, err := io.ReadFull(client, meth); err != nil {
		t.Fatal(err)
	}
	if meth[0] != 5 || meth[1] != 2 {
		t.Fatalf("method %v", meth)
	}
	auth := []byte{1, 5}
	auth = append(auth, []byte("alice")...)
	auth = append(auth, 3)
	auth = append(auth, []byte("xyz")...)
	if _, err := client.Write(auth); err != nil {
		t.Fatal(err)
	}
	st := make([]byte, 2)
	if _, err := io.ReadFull(client, st); err != nil {
		t.Fatal(err)
	}
	if st[0] != 1 || st[1] != 0 {
		t.Fatalf("auth status %v", st)
	}
	req := []byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(client, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0 {
		t.Fatalf("status %d", hdr[1])
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	if gotUser != "alice" || gotPass != "xyz" {
		t.Fatalf("user=%q pass=%q", gotUser, gotPass)
	}
}



func TestHandleTruncatedDomainLen(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	_, _ = client.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(client, make([]byte, 2))
	_, _ = client.Write([]byte{5, 1, 0, 3})
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected truncated domain")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleCloseAfterGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleCloseAfterMethodReply(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	errc := make(chan error, 1)
	go func() { errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) { return nil, nil }) }()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected truncated request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}


func TestHandleCloseAfterConnect(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	errc := make(chan error, 1)
	go func() {
		errc <- Handle(server, func(string, uint16, string, string) (io.ReadWriteCloser, error) {
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
	if _, err := client.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-errc:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}








