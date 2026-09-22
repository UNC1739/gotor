package proto

import (
	"crypto/rand"
	"io"
)

var randReader io.Reader = rand.Reader
