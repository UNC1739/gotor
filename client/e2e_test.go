package client_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adam/gotor/client"
	"github.com/adam/gotor/directory"
	"github.com/adam/gotor/sim"
	"github.com/adam/gotor/socks"
)

var (
	netw     *sim.Network
	httpURL  *url.URL
	httpHost string
	httpPort uint16
	echoAddr string
	echoHost string
	echoPort uint16
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("gotor-origin-ok\n"))
	}))
	defer hs.Close()
	u, err := url.Parse(hs.URL)
	if err != nil {
		panic(err)
	}
	httpURL = u
	httpHost = u.Hostname()
	p, _ := strconv.Atoi(u.Port())
	httpPort = uint16(p)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	echoAddr = ln.Addr().String()
	h, ps, _ := net.SplitHostPort(echoAddr)
	echoHost = h
	ep, _ := strconv.Atoi(ps)
	echoPort = uint16(ep)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()

	n, err := sim.Launch(sim.Config{ListenHost: "127.0.0.1", AdvertiseIP: "127.0.0.1"})
	if err != nil {
		panic(err)
	}
	defer n.Close()
	netw = n
	return m.Run()
}

func bootstrap(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.Bootstrap(netw.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Relays) != 3 {
		t.Fatalf("relays=%d", len(c.Relays))
	}
	return c
}

func circuit(t *testing.T, hops int) *client.Circuit {
	t.Helper()
	c := bootstrap(t)
	path, err := c.PickPath(hops)
	if err != nil {
		t.Fatal(err)
	}
	if len(path) != hops {
		t.Fatalf("path len %d want %d", len(path), hops)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = circ.Close() })
	return circ
}

func readUntil(t *testing.T, r io.Reader, want string, d time.Duration) []byte {
	t.Helper()
	errc := make(chan error, 1)
	var got []byte
	buf := make([]byte, 4096)
	go func() {
		for {
			n, err := r.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
				if strings.Contains(string(got), want) {
					errc <- nil
					return
				}
			}
			if err != nil {
				if strings.Contains(string(got), want) {
					errc <- nil
					return
				}
				errc <- err
				return
			}
		}
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("read: %v body=%q", err, got)
		}
		return got
	case <-time.After(d):
		t.Fatalf("timeout body=%q", got)
		return nil
	}
}

func TestDirectoryBootstrap(t *testing.T) {
	c := bootstrap(t)
	var sawGuard, sawExit, sawMiddle bool
	for _, r := range c.Relays {
		var zero [32]byte
		if r.NTorOnionKey == zero || r.ORPort == 0 {
			t.Fatalf("unusable relay %+v", r)
		}
		if !r.Supports("Relay", 4) || len(r.Ed25519ID) != 32 {
			t.Fatalf("missing ntor-v3 ads %+v proto=%v", r, r.Proto)
		}
		switch {
		case r.Has("Exit"):
			sawExit = true
		case r.Has("Guard"):
			sawGuard = true
		default:
			sawMiddle = true
		}
	}
	if !sawGuard || !sawExit || !sawMiddle {
		t.Fatalf("roles g=%v m=%v e=%v", sawGuard, sawMiddle, sawExit)
	}
}

func TestBeginDirConsensus(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.DialDir()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	body, err := directory.HTTPGet(st, "/tor/status-vote/current/consensus")
	if err != nil {
		t.Fatal(err)
	}
	relays, err := directory.ParseConsensus(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 3 {
		t.Fatalf("relays=%d body=%q", len(relays), body[:min(len(body), 200)])
	}
}

func TestMicrodescriptorCircuit(t *testing.T) {
	c, err := client.BootstrapMicro(netw.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Relays) != 3 {
		t.Fatalf("relays=%d", len(c.Relays))
	}
	for _, r := range c.Relays {
		if len(r.Ed25519ID) != 32 || len(r.MicroHash) != 32 {
			t.Fatalf("incomplete micro relay %+v", r)
		}
	}
	path, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = circ.Close() })
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestResolveLocalhost(t *testing.T) {
	circ := circuit(t, 3)
	ips, err := circ.Resolve("localhost")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ip := range ips {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.ParseIP("::1")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("ips=%v", ips)
	}
}

func TestPathSelectionRoles(t *testing.T) {
	c := bootstrap(t)
	p3, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	if !p3[0].Has("Guard") || !p3[2].Has("Exit") {
		t.Fatalf("3-hop roles %+v %+v %+v", p3[0].Flags, p3[1].Flags, p3[2].Flags)
	}
	if p3[0] == p3[1] || p3[1] == p3[2] || p3[0] == p3[2] {
		t.Fatal("duplicate hops")
	}
	p1, err := c.PickPath(1)
	if err != nil || len(p1) != 1 {
		t.Fatalf("%v %v", p1, err)
	}
}

func TestPathSelectionStickyGuard(t *testing.T) {
	c := bootstrap(t)
	a, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	if a[0] != b[0] {
		t.Fatalf("guard %s vs %s", a[0].Nickname, b[0].Nickname)
	}
	seen := map[string]bool{}
	for _, r := range a {
		if seen[r.Nickname] {
			t.Fatalf("duplicate %s", r.Nickname)
		}
		seen[r.Nickname] = true
	}
}

func TestPathSelectionWeightBias(t *testing.T) {
	c := bootstrap(t)
	if len(c.Relays) < 3 {
		t.Fatal("need 3 relays")
	}
	for _, r := range c.Relays {
		r.Bandwidth = 1
	}
	heavy := c.Relays[len(c.Relays)-1]
	heavy.Bandwidth = 1000
	counts := map[string]int{}
	for range 200 {
		p, err := c.PickPath(1)
		if err != nil {
			t.Fatal(err)
		}
		counts[p[0].Nickname]++
	}
	if counts[heavy.Nickname] < 150 {
		t.Fatalf("weight bias %v", counts)
	}
}

func TestPaddingThenHTTP(t *testing.T) {
	circ := circuit(t, 3)
	if err := circ.SendPadding(); err != nil {
		t.Fatal(err)
	}
	if err := circ.SendVpadding(32); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := circ.Drop(i); err != nil {
			t.Fatal(err)
		}
	}
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestOneHopHTTPEgress(t *testing.T) {
	circ := circuit(t, 1)
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestThreeHopHTTPEgress(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestMixedNtorV3Path(t *testing.T) {
	c := bootstrap(t)
	path, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	path[1].Proto = map[string][]int{"Relay": {1, 2, 3}}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = circ.Close() })
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestIPv4BeginEgress(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.Dial("127.0.0.1", httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestEchoLargePayload(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.Dial(echoHost, echoPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := make([]byte, 80*1024)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Write(want)
		done <- err
	}()
	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(st, got)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout reading echo")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload mismatch")
	}
}

func TestMultipleStreams(t *testing.T) {
	circ := circuit(t, 3)
	for i := 0; i < 4; i++ {
		st, err := circ.Dial(echoHost, echoPort)
		if err != nil {
			t.Fatal(err)
		}
		msg := bytes.Repeat([]byte{byte(i + 1)}, 2048)
		if _, err := st.Write(msg); err != nil {
			st.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil {
			st.Close()
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			st.Close()
			t.Fatalf("stream %d mismatch", i)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSendmeStreamWindow(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.Dial(echoHost, echoPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	want := make([]byte, 280*1024)
	if _, err := rand.Read(want); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := st.Write(want)
		errc <- err
	}()
	got := make([]byte, 0, len(want))
	buf := make([]byte, 8192)
	deadline := time.Now().Add(45 * time.Second)
	for len(got) < len(want) {
		if time.Now().After(deadline) {
			t.Fatalf("got %d/%d without SENDME progress", len(got), len(want))
		}
		n, err := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil && len(got) < len(want) {
			t.Fatal(err)
		}
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload mismatch")
	}
}

func TestConnectRefused(t *testing.T) {
	circ := circuit(t, 3)
	_, err := circ.Dial("127.0.0.1", 1)
	if err == nil {
		t.Fatal("expected begin failure")
	}
}

func TestOnionRejected(t *testing.T) {
	circ := circuit(t, 3)
	_, err := circ.Dial("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion", 80)
	if !errors.Is(err, client.ErrOnion) {
		t.Fatalf("got %v", err)
	}
}

func TestHandshakeIdentityMismatch(t *testing.T) {
	c := bootstrap(t)
	if len(c.Relays[0].Ed25519ID) == 0 {
		t.Fatal("missing ed25519 id")
	}
	c.Relays[0].Ed25519ID[0] ^= 0xff
	_, err := c.BuildCircuit(c.Relays[:1])
	if err == nil {
		t.Fatal("expected identity mismatch")
	}
}

func TestSOCKS5Egress(t *testing.T) {
	circ := circuit(t, 3)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = socks.Serve(ln, func(host string, port uint16) (io.ReadWriteCloser, error) {
			return circ.Dial(host, port)
		})
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var meth [2]byte
	if _, err := io.ReadFull(c, meth[:]); err != nil {
		t.Fatal(err)
	}
	host := httpHost
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	var p [2]byte
	p[0] = byte(httpPort >> 8)
	p[1] = byte(httpPort)
	req = append(req, p[:]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != 0 {
		t.Fatalf("socks status %d", hdr[1])
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, c, "gotor-origin-ok", 10*time.Second)
}

func TestTwoHopCircuit(t *testing.T) {
	circ := circuit(t, 2)
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", httpURL.Host)
	readUntil(t, st, "gotor-origin-ok", 10*time.Second)
}

func TestResolveFailure(t *testing.T) {
	circ := circuit(t, 3)
	_, err := circ.Resolve("no-such-host.invalid")
	if err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestBeginDirOneHop(t *testing.T) {
	circ := circuit(t, 1)
	st, err := circ.DialDir()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	body, err := directory.HTTPGet(st, "/tor/status-vote/current/consensus")
	if err != nil {
		t.Fatal(err)
	}
	relays, err := directory.ParseConsensus(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 3 {
		t.Fatalf("relays=%d", len(relays))
	}
}

func TestCircuitCloseThenDial(t *testing.T) {
	circ := circuit(t, 3)
	st, err := circ.Dial(httpHost, httpPort)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := circ.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := circ.Dial(httpHost, httpPort); err == nil {
		t.Fatal("expected dial on closed circuit")
	}
}

func TestBootstrapUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := client.Bootstrap(addr); err == nil {
		t.Fatal("expected unreachable")
	}
}




