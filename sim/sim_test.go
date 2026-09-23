package sim

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
	"github.com/adam/gotor/client"
	gtcrypto "github.com/adam/gotor/crypto"
	"github.com/adam/gotor/directory"
	"github.com/adam/gotor/proto"
)

func TestLaunchBadAdvertiseIP(t *testing.T) {
	if _, err := Launch(Config{AdvertiseIP: "not-an-ip", DirPort: 0}); err == nil {
		t.Fatal("expected bad advertise ip")
	}
}

func TestLaunchFetchClose(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	relays, err := directory.Fetch(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 3 {
		t.Fatalf("relays=%d", len(relays))
	}
	var guard, exit bool
	for _, r := range relays {
		if r.Has("Guard") {
			guard = true
		}
		if r.Has("Exit") {
			exit = true
		}
	}
	if !guard || !exit {
		t.Fatal("missing roles")
	}
}

func TestHasFlag(t *testing.T) {
	if !has([]string{"Guard", "Exit"}, "Exit") || has([]string{"Guard"}, "Exit") {
		t.Fatal("has")
	}
}

func startRelay(t *testing.T) *Relay {
	t.Helper()
	keys, err := generateRelayKeys("test", []string{"Guard", "Running"}, net.ParseIP("127.0.0.1"), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	r := newRelay(keys, slog.Default())
	if err := r.listen("127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func dialRelay(t *testing.T, r *Relay) *proto.Channel {
	t.Helper()
	conn, err := tls.Dial("tcp", r.Keys.Listen, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ch := proto.NewChannel(conn)
	if _, err := proto.HandshakeInitiator(ch, r.Keys.EdIDPub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	return ch
}

func createFastClient(t *testing.T, ch *proto.Channel) (uint32, *gtcrypto.Hop) {
	t.Helper()
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
	y, kh, err := cell.ParseCreatedFast(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := gtcrypto.CreateFastFinish(x, y, kh)
	if err != nil {
		t.Fatal(err)
	}
	hop, err := gtcrypto.NewHop(keys)
	if err != nil {
		t.Fatal(err)
	}
	return id, hop
}

func writeRelay(t *testing.T, ch *proto.Channel, id uint32, hop *gtcrypto.Hop, cmd byte, sid uint16, data []byte) {
	t.Helper()
	body := cell.EncodeRelay(cell.Relay{Command: cmd, StreamID: sid, Data: data})
	hop.SealForward(body)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelayEarly, Body: body}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCreateFastAndDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.CmdCreatedFast {
		t.Fatalf("cmd %d", got.Command)
	}
	y, kh, err := cell.ParseCreatedFast(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gtcrypto.CreateFastFinish(x, y, kh); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Destroy(id, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestRelayDestroyEmptyBodyThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, _ := createFastClient(t, ch)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdDestroy}); err != nil {
		t.Fatal(err)
	}
	_, _ = createFastClient(t, ch)
}

func TestRelayCreateFastSameIDOverwrite(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, _ := createFastClient(t, ch)
	x2, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x2)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayCreateFastCircIDZero(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(0, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast || got.CircID != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayCreateFastZeroX(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, make([]byte, 20))); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
	y, kh, err := cell.ParseCreatedFast(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gtcrypto.CreateFastFinish(make([]byte, 20), y, kh); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCreate2BadTypeDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, 0x50, nil)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.CmdDestroy || got.Body[0] != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestRelayCreate2TAPAndNtorV3Destroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	for _, htype := range []uint16{0x0000, 0x0001, 0x0003, 0x0004} { // TAP, reserved, ntor-v3, unknown
		id, err := proto.PickCircID(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.WriteCell(cell.Create2(id, htype, make([]byte, 84))); err != nil {
			t.Fatal(err)
		}
		got, err := ch.ReadCell()
		if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != 1 {
			t.Fatalf("htype %d %+v %v", htype, got, err)
		}
	}
}

func TestRelayCreate2NtorFailDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, gtcrypto.HTypeNtor, make([]byte, 84))); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.CmdDestroy || got.Body[0] != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestRelayCreate2NtorEmptyDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, gtcrypto.HTypeNtor, nil)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRelayIgnoresPaddingThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(cell.Padding()); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Vpadding([]byte{1})); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayIgnoresPaddingNegotiateNetinfoCerts(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdPaddingNegotiate, Body: []byte{0, 0, 0, 0, 0}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdPaddingNegotiate, Body: []byte{1, 0, 0}}); err != nil { // STOP
		t.Fatal(err)
	}

	if err := ch.WriteCell(&cell.Cell{Command: 13, Body: make([]byte, 3)}); err != nil { // PADDING_NEGOTIATED
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdAuthenticate, Body: []byte{0, 1, 2}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdVersions, Body: []byte{0, 4, 0, 5}}); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestSimBeginExtendResolve(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("gotor-origin-ok\n"))
	}))
	defer hs.Close()
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path1, err := c.PickPath(1)
	if err != nil {
		t.Fatal(err)
	}
	circ1, err := c.BuildCircuit(path1)
	if err != nil {
		t.Fatal(err)
	}
	defer circ1.Close()
	st, err := circ1.DialDir()
	if err != nil {
		t.Fatal(err)
	}
	body, err := directory.HTTPGet(st, "/tor/status-vote/current/consensus")
	st.Close()
	if err != nil || !strings.Contains(body, "network-status-version 3") {
		t.Fatalf("begin_dir %v %q", err, body)
	}

	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	path2, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	circ2, err := c.BuildCircuit(path2)
	if err != nil {
		t.Fatal(err)
	}
	defer circ2.Close()
	st2, err := circ2.Dial(u.Hostname(), uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	fmt.Fprintf(st2, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", u.Host)
	buf := make([]byte, 512)
	deadline := time.Now().Add(10 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		nread, rerr := st2.Read(buf)
		if nread > 0 {
			got = append(got, buf[:nread]...)
			if strings.Contains(string(got), "gotor-origin-ok") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(string(got), "gotor-origin-ok") {
		t.Fatalf("begin body %q", got)
	}

	eln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer eln.Close()
	go func() {
		c, err := eln.Accept()
		if err != nil {
			return
		}
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
	}()
	ep := eln.Addr().(*net.TCPAddr)
	est, err := circ2.Dial("127.0.0.1", uint16(ep.Port))
	if err != nil {
		t.Fatal(err)
	}
	defer est.Close()
	payload := bytes.Repeat([]byte{'x'}, 80*1024)
	if _, err := est.Write(payload); err != nil {
		t.Fatal(err)
	}
	gotEcho := make([]byte, 0, len(payload))
	tmp := make([]byte, 32*1024)
	deadline = time.Now().Add(15 * time.Second)
	for len(gotEcho) < len(payload) && time.Now().Before(deadline) {
		n, err := est.Read(tmp)
		if n > 0 {
			gotEcho = append(gotEcho, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(gotEcho) != len(payload) {
		t.Fatalf("echo %d/%d", len(gotEcho), len(payload))
	}

	path3, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	circ3, err := c.BuildCircuit(path3)
	if err != nil {
		t.Fatal(err)
	}
	defer circ3.Close()
	ips, err := circ3.Resolve("localhost")
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolve %v %v", ips, err)
	}
	if _, err := circ3.Dial("127.0.0.1", 1); err == nil {
		t.Fatal("expected connect refused")
	}
}

func TestRelayBeginDirNotDirectory(t *testing.T) {
	r := startRelay(t)
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	if _, err := circ.DialDir(); err == nil {
		t.Fatal("expected not directory")
	}
}

func TestRelayIgnoresTAPCreate(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdCreate, Body: make([]byte, 186)}); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayDropThenHTTP(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer hs.Close()
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(1)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	if err := circ.Drop(0); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	st, err := circ.Dial(u.Hostname(), uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", u.Host)
	buf := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		n, rerr := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if strings.Contains(string(got), "ok") {
				return
			}
		}
		if rerr != nil {
			break
		}
	}
	t.Fatalf("body %q", got)
}

func TestRelayBeginDirUnreachable(t *testing.T) {
	r := startRelay(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	r.DirAddr = addr
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	if _, err := circ.DialDir(); err == nil {
		t.Fatal("expected dir dial fail")
	}
}

func TestRelayExtendDialFail(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	path[1].ORPort = 1
	if _, err := c.BuildCircuit(path); err == nil {
		t.Fatal("expected extend fail")
	}
}

func TestRelayExtendHandshakeFail(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*tc}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Read(buf)
	}()
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	ta := ln.Addr().(*net.TCPAddr)
	path[1].Address = ta.IP
	path[1].ORPort = uint16(ta.Port)
	if _, err := c.BuildCircuit(path); err == nil {
		t.Fatal("expected extend handshake fail")
	}
}

func TestDir404(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, path := range []string{
		"/not-a-dir-path",
		"/tor/server/fp/deadbeef",
	} {

		resp, err := http.Get("http://" + n.DirAddr() + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestRelayTLSHandshakeFail(t *testing.T) {
	r := startRelay(t)
	conn, err := net.Dial("tcp", r.Keys.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 16)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
}

func TestRelayHandshakeResponderFail(t *testing.T) {
	r := startRelay(t)
	conn, err := tls.Dial("tcp", r.Keys.Listen, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("not-a-versions-cell"))
	buf := make([]byte, 16)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)
}

func TestRelayDestroyUnknownThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(cell.Destroy(0x1234, 0)); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayDestroyMaxCircIDThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(cell.Destroy(0xffffffff, 11)); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayCreated2UnexpectedThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	if err := ch.WriteCell(cell.Created2(0x99, make([]byte, 64))); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestResolveNXDOMAIN(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(1)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	if _, err := circ.Resolve("no-such-host.invalid"); err == nil {
		t.Fatal("expected resolve fail")
	}
}

func TestDirAddrNil(t *testing.T) {
	n := &Network{}
	if n.DirAddr() != "" {
		t.Fatalf("got %q", n.DirAddr())
	}
}

func TestRelayExtend2MalformedDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayExtend2, 0, []byte{0x05})
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != cell.DestroyProtocol {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayExtend2NoIPv4Destroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	// nspec=1 LS_IPV6 (type 1) + 16-byte addr + 2-byte port, then empty ntor handshake
	data := []byte{1, 0x01, 18}
	data = append(data, make([]byte, 18)...)
	data = append(data, 0, 2, 0, 0) // htype ntor, hlen 0
	writeRelay(t, ch, id, hop, cell.RelayExtend2, 0, data)
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != cell.DestroyProtocol {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayExtend2NoLinkSpecsDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayExtend2, 0, []byte{0, 0, 2, 0, 0}) // nspec=0, htype ntor, hlen 0
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != cell.DestroyProtocol {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayExtend2TwoIPv4Destroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	data := []byte{2, 0, 6, 1, 2, 3, 4, 0x23, 0x29, 0, 6, 5, 6, 7, 8, 0x23, 0x29, 0, 2, 0, 0}
	writeRelay(t, ch, id, hop, cell.RelayExtend2, 0, data)
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdDestroy || got.Body[0] != cell.DestroyConnectFailed {

		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayBeginBadAddress(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte("noport"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
		t.Fatalf("cmd %d", got.Command)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != cell.RelayEnd || len(msg.Data) < 1 || msg.Data[0] != cell.EndReasonMisc {
		t.Fatalf("%+v", msg)
	}
}

func TestRelayTruncateIgnoredThenBeginDir(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayTruncate, 0, nil)
	writeRelay(t, ch, id, hop, cell.RelayBeginDir, 1, []byte("junk"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
		t.Fatalf("cmd %d", got.Command)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != cell.RelayEnd {
		t.Fatalf("cmd %d", msg.Command)
	}
}

func TestRelayHandleConnNotTLS(t *testing.T) {
	r := startRelay(t)
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		r.handleConn(a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestEnsureServeIdempotent(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	var guard *Relay
	for _, rel := range n.relays {
		if rel.Keys.Nickname == path[0].Nickname {
			guard = rel
			break
		}
	}
	if guard == nil {
		t.Fatal("no guard")
	}
	guard.mu.Lock()
	var chs []*proto.Channel
	for ch := range guard.serving {
		chs = append(chs, ch)
	}
	guard.mu.Unlock()
	if len(chs) == 0 {
		t.Fatal("no serving channel")
	}
	for _, ch := range chs {
		guard.ensureServe(ch)
	}
}

func TestRelaySendmeBadDigestDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelaySendme, 0, cell.EncodeSendmeV1(make([]byte, 20)))
	_, _ = createFastClient(t, ch)
}

func TestRelaySendmeUnknownStream(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelaySendme, 99, nil)
	_, _ = createFastClient(t, ch)
}

func TestRelayTwoCreateFastOnOneLink(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	x1, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x2, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id1, x1)); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id2, x2)); err != nil {
		t.Fatal(err)
	}
	got1, err := ch.ReadCell()
	if err != nil || got1.Command != cell.CmdCreatedFast {
		t.Fatalf("first %v %v", got1, err)
	}
	got2, err := ch.ReadCell()
	if err != nil || got2.Command != cell.CmdCreatedFast {
		t.Fatalf("second %v %v", got2, err)
	}
	if got1.CircID == got2.CircID {
		t.Fatal("same circid")
	}
}

func TestRelayCreateFastShortDestroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	r.onCreateFast(ch, &cell.Cell{CircID: id, Command: cell.CmdCreateFast, Body: []byte{1, 2, 3}})
}

func TestRelayUnrecognizedThenCreateFast(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, _ := createFastClient(t, ch)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelay, Body: make([]byte, cell.BodyLen)}); err != nil {
		t.Fatal(err)
	}
	_, _ = createFastClient(t, ch)
}

func TestRelayDataUnknownStream(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayData, 99, []byte("x"))
	writeRelay(t, ch, id, hop, cell.RelayBeginDir, 1, nil)
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayEnd {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelaySendmeV0Destroy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelaySendme, 0, nil)
	_, _ = createFastClient(t, ch)
}

func TestRelayInvalidLengthIgnored(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	body := make([]byte, cell.BodyLen)
	body[0] = cell.RelayBegin
	body[9] = 0x13
	body[10] = 0x88 // length 5000
	hop.SealForward(body)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelay, Body: body}); err != nil {
		t.Fatal(err)
	}
	_, _ = createFastClient(t, ch)
}

func TestRelayDestroyOpenStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	if err := ch.WriteCell(cell.Destroy(id, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCreateFastWriteFail(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ch.Close()
	r.onCreateFast(ch, cell.CreateFast(id, x))
}

func TestRelayCreate2WriteFail(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	hs, _, err := gtcrypto.NtorClientHandshake(rand.Reader, r.Keys.Identity, r.Keys.NTor.Public)
	if err != nil {
		t.Fatal(err)
	}
	_ = ch.Close()
	r.onCreate2(ch, cell.Create2(id, gtcrypto.HTypeNtor, hs))
}

func TestRelayExtendIPv6OnlyFail(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	path[1].Address = net.ParseIP("::1")
	if _, err := c.BuildCircuit(path); err == nil {
		t.Fatal("expected ipv6 extend fail")
	}
}

func TestRelayExtendMalformedCreated2(t *testing.T) {
	keys, err := generateRelayKeys("mute", nil, net.IPv4(127, 0, 0, 1), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", keys.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tc, ok := conn.(*tls.Conn)
		if !ok {
			return
		}
		if err := tc.Handshake(); err != nil {
			return
		}
		ch := proto.NewChannel(tc)
		if err := proto.HandshakeResponder(ch, keys.Responder()); err != nil {
			return
		}
		for {
			c, err := ch.ReadCell()
			if err != nil {
				return
			}
			if c.Command == cell.CmdCreate2 {
				_ = ch.WriteCell(&cell.Cell{CircID: c.CircID, Command: cell.CmdCreated2, Body: []byte{0x02, 0x00}})
			}
		}
	}()
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	ta := ln.Addr().(*net.TCPAddr)
	path[1].Address = ta.IP
	path[1].ORPort = uint16(ta.Port)
	path[1].Identity = keys.Identity
	copy(path[1].NTorOnionKey[:], keys.NTor.Public[:])
	path[1].Ed25519ID = keys.EdIDPub
	if _, err := c.BuildCircuit(path); err == nil {
		t.Fatal("expected malformed CREATED2 extend fail")
	}
}

func TestRelayListenFail(t *testing.T) {
	r := startRelay(t)
	r2 := newRelay(r.Keys, slog.Default())
	if err := r2.listen("::1", 0); err == nil {
		t.Fatal("expected listen fail")
	}
}

func TestInstallHopBadKeys(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	_, err := r.installHop(ch, 1, &gtcrypto.CircuitKeys{
		Kf: []byte{1},
		Kb: []byte{1},
		Df: make([]byte, 20),
		Db: make([]byte, 20),
	})
	if err == nil {
		t.Fatal("expected bad keys")
	}
}

func TestRelayCreate2NtorRoundTrip(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	hs, st, err := gtcrypto.NtorClientHandshake(rand.Reader, r.Keys.Identity, r.Keys.NTor.Public)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, gtcrypto.HTypeNtor, hs)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreated2 {
		t.Fatalf("%v %v", got, err)
	}
	hdata, err := cell.ParseCreated2(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Finish(hdata); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCreate2AfterCreateFastSameID(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, _ := createFastClient(t, ch)
	hs, st, err := gtcrypto.NtorClientHandshake(rand.Reader, r.Keys.Identity, r.Keys.NTor.Public)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, gtcrypto.HTypeNtor, hs)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreated2 {
		t.Fatalf("%v %v", got, err)
	}
	hdata, err := cell.ParseCreated2(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Finish(hdata); err != nil {
		t.Fatal(err)
	}
}

func TestRelayCreateFastAfterCreate2SameID(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	hs, st, err := gtcrypto.NtorClientHandshake(rand.Reader, r.Keys.Identity, r.Keys.NTor.Public)
	if err != nil {
		t.Fatal(err)
	}
	id, err := proto.PickCircID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Create2(id, gtcrypto.HTypeNtor, hs)); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreated2 {
		t.Fatalf("%v %v", got, err)
	}
	hdata, err := cell.ParseCreated2(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Finish(hdata); err != nil {
		t.Fatal(err)
	}
	x, err := gtcrypto.CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.CreateFast(id, x)); err != nil {
		t.Fatal(err)
	}
	got, err = ch.ReadCell()
	if err != nil || got.Command != cell.CmdCreatedFast {
		t.Fatalf("%v %v", got, err)
	}
}

func TestRelayBeginIPv6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	payload := append([]byte(fmt.Sprintf("::1:%d", port)), 0, 0, 0, 0, byte(cell.BeginIPv6OK))
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, payload)

	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayBeginFlagsIPv4Required(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	payload := append([]byte(fmt.Sprintf("127.0.0.1:%d", port)), 0, 0, 0, 0, 0x09) // IPv6OK|IPv4Required
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, payload)
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayEndAfterConnected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelayEnd, 1, []byte{cell.EndReasonDone})
	writeRelay(t, ch, id, hop, cell.RelayData, 1, []byte("late"))
}

func TestRelayDataEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if n > 0 {
			_, _ = c.Write(buf[:n])
		}
		_ = err
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelayData, 1, []byte("ping"))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err = ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err = cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData && string(msg.Data) == "ping" {
			return
		}
	}
	t.Fatal("no echoed data")
}

func TestRelayStreamSendme(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelaySendme, 1, nil)
	writeRelay(t, ch, id, hop, cell.RelayData, 1, []byte("x"))
}

func TestRelayDestroyInflightData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelayData, 1, []byte("hello"))
	if err := ch.WriteCell(cell.Destroy(id, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestRelayResolveEmpty(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayResolve, 2, []byte{0})
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayResolved {
		t.Fatalf("%v %v", msg, err)
	}
	ans, err := cell.ParseResolved(msg.Data)
	if err != nil || len(ans) == 0 || ans[0].Type != cell.ResolvedErr {
		t.Fatalf("%+v %v", ans, err)
	}
}

func TestRelayResolveOnion(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayResolve, 2, cell.EncodeResolve("aaaaaaaaaaaaaaaa.onion"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayResolved {
		t.Fatalf("%v %v", msg, err)
	}
	ans, err := cell.ParseResolved(msg.Data)
	if err != nil || len(ans) == 0 || ans[0].Type != cell.ResolvedErr {
		t.Fatalf("%+v %v", ans, err)
	}
}

func TestRelayBeginWithFlags(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, cell.BeginPayloadFlags("127.0.0.1", port, cell.BeginIPv6OK))

	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelayData, 1, nil)

}

func TestRelayDropMiddleThenHTTP(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer hs.Close()
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(3)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	if err := circ.Drop(1); err != nil {
		t.Fatal(err)
	}
	if err := circ.Drop(2); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	st, err := circ.Dial(u.Hostname(), uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fmt.Fprintf(st, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", u.Host)
	buf := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		n, rerr := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if strings.Contains(string(got), "ok") {
				return
			}
		}
		if rerr != nil {
			break
		}
	}
	t.Fatalf("body %q", got)
}

func TestRelayPaddingDuringCircuitThenBegin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	if err := ch.WriteCell(cell.Padding()); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Vpadding(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	writeRelay(t, ch, id, hop, cell.RelayDrop, 0, []byte("ignore-me"))

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayResolveIPv4Literal(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayResolve, 2, cell.EncodeResolve("127.0.0.1"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayResolved {
		t.Fatalf("%v %v", msg, err)
	}
	ans, err := cell.ParseResolved(msg.Data)
	if err != nil || len(ans) == 0 || ans[0].Type != cell.ResolvedIPv4 {
		t.Fatalf("%+v %v", ans, err)
	}
	if string(ans[0].Value) != string(net.IPv4(127, 0, 0, 1).To4()) {
		t.Fatalf("ip %x", ans[0].Value)
	}
}

func TestRelayTwoStreams(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	accept := func(ln net.Listener) {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}
	go accept(ln1)
	go accept(ln2)
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	p1 := uint16(ln1.Addr().(*net.TCPAddr).Port)
	p2 := uint16(ln2.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", p1)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected || msg.StreamID != 1 {
		t.Fatalf("%v %v", msg, err)
	}
	writeRelay(t, ch, id, hop, cell.RelayBegin, 2, []byte(fmt.Sprintf("127.0.0.1:%d", p2)))
	got, err = ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err = cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected || msg.StreamID != 2 {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayBeginOnRelayCell(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if n > 0 {
			_, _ = c.Write(buf[:n])
		}
		_ = err
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	body := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte(fmt.Sprintf("127.0.0.1:%d", port))})
	hop.SealForward(body)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelay, Body: body}); err != nil {
		t.Fatal(err)
	}
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	data := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("ping")})
	hop.SealForward(data)
	if err := ch.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelay, Body: data}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err = ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err = cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData && string(msg.Data) == "ping" {
			return
		}
	}
	t.Fatal("no echo")

}

func TestRelayResolveIPv6Literal(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayResolve, 2, cell.EncodeResolve("::1"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayResolved {
		t.Fatalf("%v %v", msg, err)
	}
	ans, err := cell.ParseResolved(msg.Data)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, a := range ans {
		if a.Type == cell.ResolvedIPv6 && len(a.Value) == 16 {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("no ipv6 %+v", ans)
	}
}

func TestRelayBeginHostname(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("localhost:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayBeginConnectedIPv4Payload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayConnected {
		t.Fatalf("%v %v", msg, err)
	}
	if len(msg.Data) != 8 {
		t.Fatalf("connected payload %d", len(msg.Data))
	}
}

func TestRelayEndDoneWhenPeerCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	deadline := time.Now().Add(5 * time.Second)
	var sawEnd bool
	for time.Now().Before(deadline) {
		got, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err := cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayEnd {
			if len(msg.Data) < 1 || msg.Data[0] != cell.EndReasonDone {
				t.Fatalf("end reason %v", msg.Data)
			}
			sawEnd = true
			break
		}
	}
	if !sawEnd {
		t.Fatal("no RELAY_END")
	}
}

func TestRelayStreamWindowStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		payload := bytes.Repeat([]byte{'x'}, cell.MaxRelayData)
		for range 600 {
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	n := 0
	deadline := time.Now().Add(15 * time.Second)
	for n < 500 && time.Now().Before(deadline) {
		got, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err := cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData {
			n++
		}
	}
	if n != 500 {
		t.Fatalf("before sendme %d", n)
	}
	writeRelay(t, ch, id, hop, cell.RelaySendme, 1, nil)
	gotMore := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err := cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData {
			gotMore = true
			break
		}
	}
	if !gotMore {
		t.Fatal("expected data after stream SENDME")
	}
}

func TestRelayCreated2DroppedWhenBusy(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, _ := createFastClient(t, ch)
	r.mu.Lock()
	var ci *circuit
	var srvCh *proto.Channel
	for k, c := range r.inbound {
		ci = c
		srvCh = k.ch
		id = k.id
		break
	}
	r.mu.Unlock()
	if ci == nil || srvCh == nil {
		t.Fatal("no circuit")
	}
	ci.extendWait = make(chan *cell.Cell, 1)
	ci.extendWait <- &cell.Cell{Command: cell.CmdCreated2}
	r.mu.Lock()
	r.outbound[circKey{srvCh, id}] = ci
	r.mu.Unlock()
	r.onCreated2(srvCh, cell.Created2(id, []byte{1}))
	if len(ci.extendWait) != 1 {
		t.Fatalf("queued %d", len(ci.extendWait))
	}
}

func TestRelayDropOutboundChannel(t *testing.T) {
	n, err := Launch(Config{DirPort: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	c, err := client.Bootstrap(n.DirAddr())
	if err != nil {
		t.Fatal(err)
	}
	path, err := c.PickPath(2)
	if err != nil {
		t.Fatal(err)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	var guard *Relay
	for _, rel := range n.relays {
		if rel.Keys.Nickname == path[0].Nickname {
			guard = rel
			break
		}
	}
	if guard == nil {
		t.Fatal("no guard")
	}
	guard.mu.Lock()
	var out []*proto.Channel
	for ch := range guard.serving {
		out = append(out, ch)
	}
	guard.mu.Unlock()
	if len(out) == 0 {
		t.Fatal("no outbound")
	}
	for _, ch := range out {
		_ = ch.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		guard.mu.Lock()
		nserve := len(guard.serving)
		guard.mu.Unlock()
		if nserve == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("outbound serving still set")
}

func TestDirAddrEmptyAdvertiseIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	n := &Network{cfg: Config{}, dirLn: ln}
	got := n.DirAddr()
	if got == "" || got[:9] != "127.0.0.1" {
		t.Fatalf("DirAddr %q", got)
	}
}

func TestLaunchDirPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if _, err := Launch(Config{DirPort: port}); err == nil {
		t.Fatal("expected dirport in use")
	}
}

func TestRelayBeginUnusableAddress(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte("0.0.0.0:1"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayEnd {
		t.Fatalf("%v %v", msg, err)
	}
	if len(msg.Data) < 1 || msg.Data[0] != cell.EndReasonConnectRefused {
		t.Fatalf("reason %v", msg.Data)
	}
}

func TestRelayCircSendmeV1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		payload := bytes.Repeat([]byte{'x'}, cell.MaxRelayData)
		for range 150 {
			if _, err := c.Write(payload); err != nil {
				return
			}
		}
	}()
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte(fmt.Sprintf("127.0.0.1:%d", port)))
	n := 0
	var dig []byte
	deadline := time.Now().Add(15 * time.Second)
	for n < 100 && time.Now().Before(deadline) {
		got, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err := cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData {
			n++
			if n == cell.CircWindowInc {
				dig = append([]byte(nil), hop.BackwardDigest()...)
			}
		}
	}
	if n != 100 || len(dig) < 20 {
		t.Fatalf("data=%d dig=%d", n, len(dig))
	}
	writeRelay(t, ch, id, hop, cell.RelaySendme, 0, cell.EncodeSendmeV1(dig))
	gotMore := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command == cell.CmdDestroy {
			t.Fatal("SENDME v1 destroyed circuit")
		}
		if got.Command != cell.CmdRelay && got.Command != cell.CmdRelayEarly {
			continue
		}
		hop.DecryptBackward(got.Body)
		if !hop.RecognizeBackward(got.Body) {
			continue
		}
		msg, err := cell.DecodeRelay(got.Body)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Command == cell.RelayData {
			gotMore = true
			break
		}
	}
	if !gotMore {
		t.Fatal("expected data after circ SENDME v1")
	}
}

func TestGenerateRelayKeysIPv6Advertise(t *testing.T) {
	keys, err := generateRelayKeys("v6", nil, net.ParseIP("::1"), []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if keys.AdvertiseIP.To16() == nil || keys.TLS == nil {
		t.Fatal("ipv6 keys")
	}
}

func TestLaunchListenHostFail(t *testing.T) {
	if _, err := Launch(Config{ListenHost: "::1", DirPort: 0}); err == nil {
		t.Fatal("expected listen fail")
	}
}

func TestRelayBeginPortZero(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte("127.0.0.1:0"))
	got, err := ch.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	hop.DecryptBackward(got.Body)
	if !hop.RecognizeBackward(got.Body) {
		t.Fatal("not recognized")
	}
	msg, err := cell.DecodeRelay(got.Body)
	if err != nil || msg.Command != cell.RelayEnd {
		t.Fatalf("%v %v", msg, err)
	}
}

func TestRelayDialAfterClose(t *testing.T) {
	r := startRelay(t)
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	if err := circ.Close(); err != nil {
		t.Fatal(err)
	}
	_ = circ.Close()
	if _, err := circ.Dial("127.0.0.1", 80); err == nil {
		t.Fatal("expected dial after close")
	}

}

func TestRelayWriteAfterCircuitClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	st, err := circ.Dial("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if err := circ.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write after circuit close")
	}
}

func TestRelayResolveAfterClose(t *testing.T) {
	r := startRelay(t)
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	if err := circ.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := circ.Resolve("localhost"); err == nil {
		t.Fatal("expected resolve after close")
	}
}

func TestRelayClientStreamClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()
	r := startRelay(t)
	rel := &directory.Relay{
		Nickname:  r.Keys.Nickname,
		Address:   net.ParseIP("127.0.0.1"),
		ORPort:    r.Keys.ORPort,
		Ed25519ID: r.Keys.EdIDPub,
		Identity:  r.Keys.Identity,
	}
	copy(rel.NTorOnionKey[:], r.Keys.NTor.Public[:])
	c := &client.Client{}
	circ, err := c.BuildCircuit([]*directory.Relay{rel})
	if err != nil {
		t.Fatal(err)
	}
	defer circ.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	st, err := circ.Dial("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	n, err := st.Read(make([]byte, 8))
	if n != 0 || err == nil {
		t.Fatalf("read after close n=%d err=%v", n, err)
	}
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatal("write after close")
	}

}

func TestRelayDestroyThenRelayIgnored(t *testing.T) {
	r := startRelay(t)
	ch := dialRelay(t, r)
	id, hop := createFastClient(t, ch)
	if err := ch.WriteCell(cell.Destroy(id, 0)); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Destroy(id, 1)); err != nil {
		t.Fatal(err)
	}
	writeRelay(t, ch, id, hop, cell.RelayBegin, 1, []byte("127.0.0.1:80"))
	_, _ = createFastClient(t, ch)

}
