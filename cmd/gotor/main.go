package main

import (
	"io"
	"log/slog"
	"net"
	"os"

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
	path, err := c.PickPath(3)
	if err != nil {
		log.Error("path selection failed", "err", err)
		os.Exit(1)
	}
	for i, r := range path {
		log.Info("path hop", "i", i, "nick", r.Nickname, "addr", r.Address, "or", r.ORPort)
	}
	circ, err := c.BuildCircuit(path)
	if err != nil {
		log.Error("circuit build failed", "err", err)
		os.Exit(1)
	}
	log.Info("circuit built", "hops", 3)
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Error("socks listen failed", "err", err)
		os.Exit(1)
	}
	log.Info("socks5 listening", "addr", ln.Addr().String())
	err = socks.Serve(ln, func(host string, port uint16) (io.ReadWriteCloser, error) {
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
