package sim

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	ListenHost  string
	AdvertiseIP string
	DirPort     int
	Hosts       []string
}

type Network struct {
	cfg       Config
	relays    []*Relay
	authority *rsa.PrivateKey
	dirLn     net.Listener
	dirSrv    *http.Server
	log       *slog.Logger
	hsMu      sync.Mutex
	hs        map[string]string
}

func Launch(cfg Config) (*Network, error) {
	if cfg.ListenHost == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	if cfg.AdvertiseIP == "" {
		cfg.AdvertiseIP = "127.0.0.1"
	}
	adv := net.ParseIP(cfg.AdvertiseIP)
	if adv == nil {
		return nil, fmt.Errorf("bad advertise ip %q", cfg.AdvertiseIP)
	}
	log := slog.Default()
	hosts := append([]string{"localhost", "tornet"}, cfg.Hosts...)
	roles := []struct {
		name  string
		flags []string
	}{
		{"gotor1", []string{"Guard"}},
		{"gotor2", []string{}},
		{"gotor3", []string{"Exit"}},
	}
	n := &Network{cfg: cfg, log: log, hs: map[string]string{}}
	auth, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("authority key: %w", err)
	}
	n.authority = auth
	for _, role := range roles {
		keys, err := generateRelayKeys(role.name, role.flags, adv, hosts)
		if err != nil {
			n.Close()
			return nil, err
		}
		r := newRelay(keys, log)
		if err := r.listen(cfg.ListenHost, 0); err != nil {
			n.Close()
			return nil, err
		}
		n.relays = append(n.relays, r)
		log.Info("relay listening", "name", role.name, "or", r.Keys.Listen, "fp", fmt.Sprintf("%x", keys.Identity))
	}
	addr := net.JoinHostPort(cfg.ListenHost, fmt.Sprintf("%d", cfg.DirPort))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		n.Close()
		return nil, err
	}
	n.dirLn = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/", n.serveDir)
	n.dirSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = n.dirSrv.Serve(ln) }()
	dir := n.DirAddr()
	for _, r := range n.relays {
		r.DirAddr = dir
	}
	log.Info("directory listening", "addr", dir)
	return n, nil
}

func (n *Network) DirAddr() string {
	if n.dirLn == nil {
		return ""
	}
	ta := n.dirLn.Addr().(*net.TCPAddr)
	host := n.cfg.AdvertiseIP
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", ta.Port))
}

func (n *Network) Close() {
	if n.dirSrv != nil {
		_ = n.dirSrv.Close()
	}
	if n.dirLn != nil {
		_ = n.dirLn.Close()
	}
	for _, r := range n.relays {
		r.Close()
	}
}
