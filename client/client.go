package client

import (
	"log/slog"

	"github.com/adam/gotor/directory"
)

type Client struct {
	DirAddr string
	Relays  []*directory.Relay
	Guard   *directory.Relay
	Log     *slog.Logger
}

func Bootstrap(dirAddr string) (*Client, error) {
	relays, err := directory.Fetch(dirAddr)
	if err != nil {
		return nil, err
	}
	return &Client{DirAddr: dirAddr, Relays: relays, Log: slog.Default()}, nil
}

func BootstrapMicro(dirAddr string) (*Client, error) {
	relays, err := directory.FetchMicro(dirAddr)
	if err != nil {
		return nil, err
	}
	return &Client{DirAddr: dirAddr, Relays: relays, Log: slog.Default()}, nil
}
