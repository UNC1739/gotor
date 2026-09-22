//go:build publicnet

package client_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/adam/gotor/client"
)

const defconOnion = "ezdhgsy2aw7zg54z6dqsutrduhl22moami5zv2zt6urr6vub7gs6wfad.onion"

func TestDialOnionDEFCON(t *testing.T) {
	c, err := client.BootstrapPublic()
	if err != nil {
		t.Fatal(err)
	}
	var last error
	for _, port := range []uint16{80, 443} {
		s, err := c.DialOnion(defconOnion, port)
		if err != nil {
			last = err
			t.Logf("port %d: %v", port, err)
			continue
		}
		defer s.Close()
		if _, err := io.WriteString(s, "GET / HTTP/1.0\r\nHost: "+defconOnion+"\r\n\r\n"); err != nil {
			last = err
			t.Logf("port %d write: %v", port, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(s, 64<<10))
		if err != nil && len(body) == 0 {
			last = err
			t.Logf("port %d read: %v", port, err)
			continue
		}
		low := strings.ToLower(string(body))
		if !strings.Contains(low, "http/") && !strings.Contains(low, "defcon") && !strings.Contains(low, "html") {
			last = fmt.Errorf("unexpected body %q", trimBody(body))
			t.Logf("port %d body: %s", port, trimBody(body))
			continue
		}
		t.Logf("defcon onion port %d: %s", port, trimBody(body))
		return
	}
	if last == nil {
		last = fmt.Errorf("no port answered")
	}
	t.Fatal(last)
}

func trimBody(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
