package main

import (
	"log/slog"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("ORIGIN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("gotor-origin-ok\n"))
	})
	slog.Info("origin listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("origin failed", "err", err)
		os.Exit(1)
	}
}
