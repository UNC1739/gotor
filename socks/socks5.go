package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/adam/gotor/cell"
)

func Serve(ln net.Listener, dial func(host string, port uint16, user, pass string) (io.ReadWriteCloser, error)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			_ = Handle(c, dial)
			_ = c.Close()
		}()
	}
}

func Handle(c net.Conn, dial func(host string, port uint16, user, pass string) (io.ReadWriteCloser, error)) error {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return fmt.Errorf("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	user, pass, err := negotiateAuth(c, methods)
	if err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	if req[0] != 5 || req[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported socks command")
	}
	host, port, err := readAddr(c, req[3])
	if err != nil {
		return err
	}
	rw, err := dial(host, port, user, pass)
	if err != nil {
		status := byte(1)
		var end cell.EndError
		if errors.As(err, &end) && end.Reason == cell.EndReasonConnectRefused {
			status = 5
		}
		_, _ = c.Write([]byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer rw.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(rw, c); errc <- e }()
	go func() { _, e := io.Copy(c, rw); errc <- e }()
	<-errc
	return nil
}

func negotiateAuth(c net.Conn, methods []byte) (user, pass string, err error) {
	want := byte(0)
	for _, m := range methods {
		if m == 2 {
			want = 2
			break
		}
		if m == 0 {
			want = 0
		}
	}
	if !hasMethod(methods, want) {
		_, _ = c.Write([]byte{5, 0xff})
		return "", "", fmt.Errorf("no acceptable socks method")
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return "", "", err
	}
	if want == 0 {
		return "", "", nil
	}
	var uh [2]byte
	if _, err := io.ReadFull(c, uh[:]); err != nil {
		return "", "", err
	}
	if uh[0] != 1 {
		return "", "", fmt.Errorf("bad socks5 auth version")
	}
	ub := make([]byte, uh[1])
	if _, err := io.ReadFull(c, ub); err != nil {
		return "", "", err
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return "", "", err
	}
	pb := make([]byte, pl[0])
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", "", err
	}
	if _, err := c.Write([]byte{1, 0}); err != nil {
		return "", "", err
	}
	return string(ub), string(pb), nil
}

func hasMethod(methods []byte, m byte) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	switch atyp {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", 0, err
		}
		port, err := readPort(r)
		return net.IP(a[:]).String(), port, err
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", 0, err
		}
		port, err := readPort(r)
		return net.IP(a[:]).String(), port, err
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}
		host := make([]byte, n[0])
		if _, err := io.ReadFull(r, host); err != nil {
			return "", 0, err
		}
		port, err := readPort(r)
		return string(host), port, err
	default:
		return "", 0, fmt.Errorf("bad atyp %d", atyp)
	}
}

func readPort(r io.Reader) (uint16, error) {
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(p[:]), nil
}

func HostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
