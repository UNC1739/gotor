package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/adam/gotor/client"
	"github.com/adam/gotor/socks"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	dir := env("GOTOR_DIR", "127.0.0.1:7000")
	socksAddr := env("GOTOR_SOCKS", "0.0.0.0:9050")

	log.Info("bootstrapping", "dir", dir)
	c, err := client.Bootstrap(dir)
	if err != nil {
		log.Error("bootstrap failed", "err", err)
		os.Exit(1)
	}
	log.Info("directory fetched", "relays", len(c.Relays))
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Error("socks listen failed", "err", err)
		os.Exit(1)
	}
	log.Info("socks5 listening", "addr", ln.Addr().String())
	err = socks.Serve(ln, func(host string, port uint16, user, pass string) (io.ReadWriteCloser, error) {
		if strings.HasSuffix(strings.ToLower(host), ".onion") {
			return c.DialOnion(host, port)
		}
		circ, err := c.CircuitFor(user, pass)
		if err != nil {
			return nil, err
		}
		return circ.Dial(host, port)
	})
	if err != nil {
		log.Error("socks serve failed", "err", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
