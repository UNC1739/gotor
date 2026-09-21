package proto

import "crypto/rand"

func randReader() *randReaderT { return &randReaderT{} }

type randReaderT struct{}

func (*randReaderT) Read(p []byte) (int, error) { return rand.Read(p) }
