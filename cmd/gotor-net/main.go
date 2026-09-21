package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/adam/gotor/sim"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	cfg := sim.Config{
		ListenHost:  env("GOTOR_LISTEN", "0.0.0.0"),
		AdvertiseIP: env("GOTOR_ADVERTISE", "127.0.0.1"),
		DirPort:     7000,
		Hosts:       []string{"tornet", "localhost"},
	}
	n, err := sim.Launch(cfg)
	if err != nil {
		log.Error("failed to start simulated tor network", "err", err)
		os.Exit(1)
	}
	defer n.Close()
	log.Info("simulated tor network ready", "dir", n.DirAddr())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
