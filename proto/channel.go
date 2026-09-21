package proto

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/adam/gotor/cell"
)

type Channel struct {
	Conn      *tls.Conn
	LinkVer   int
	CircIDLen int
	r         *bufio.Reader
	wmu       sync.Mutex

	mu       sync.Mutex
	handlers map[uint32]chan *cell.Cell
	closed   chan struct{}
	closeErr error
}

func NewChannel(conn *tls.Conn) *Channel {
	return &Channel{
		Conn:      conn,
		CircIDLen: 2,
		r:         bufio.NewReader(conn),
		handlers:  map[uint32]chan *cell.Cell{},
		closed:    make(chan struct{}),
	}
}

func (ch *Channel) RemoteAddr() net.Addr { return ch.Conn.RemoteAddr() }

func (ch *Channel) PeerTLSDigest() []byte {
	st := ch.Conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	sum := [32]byte{}
	copy(sum[:], st.PeerCertificates[0].Raw)
	return st.PeerCertificates[0].Raw
}

func (ch *Channel) WriteCell(c *cell.Cell) error {
	ch.wmu.Lock()
	defer ch.wmu.Unlock()
	return c.Write(ch.Conn, ch.CircIDLen)
}

func (ch *Channel) WriteVersions(versions ...uint16) error {
	ch.wmu.Lock()
	defer ch.wmu.Unlock()
	return cell.Versions(2, versions...).Write(ch.Conn, 2)
}

func (ch *Channel) ReadCell() (*cell.Cell, error) {
	return cell.Read(ch.r, ch.CircIDLen)
}

func (ch *Channel) ReadVersions() (*cell.Cell, error) {
	return cell.Read(ch.r, 2)
}

func (ch *Channel) SetLinkVersion(v int) {
	ch.LinkVer = v
	ch.CircIDLen = cell.CircIDLen(v)
}

func (ch *Channel) Subscribe(circID uint32) <-chan *cell.Cell {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	c := make(chan *cell.Cell, 64)
	ch.handlers[circID] = c
	return c
}

func (ch *Channel) Unsubscribe(circID uint32) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if c, ok := ch.handlers[circID]; ok {
		delete(ch.handlers, circID)
		close(c)
	}
}

func (ch *Channel) StartReadLoop() {
	go ch.readLoop()
}

func (ch *Channel) readLoop() {
	defer ch.shutdown()
	for {
		c, err := ch.ReadCell()
		if err != nil {
			if err != io.EOF {
				ch.mu.Lock()
				ch.closeErr = err
				ch.mu.Unlock()
			}
			return
		}
		if c.Command == cell.CmdPadding || c.Command == cell.CmdVpadding {
			continue
		}
		ch.mu.Lock()
		h := ch.handlers[c.CircID]
		zero := ch.handlers[0]
		ch.mu.Unlock()
		if h != nil {
			select {
			case h <- c:
			case <-ch.closed:
				return
			}
			continue
		}
		if zero != nil && c.CircID != 0 {
			select {
			case zero <- c:
			default:
			}
		}
	}
}

func (ch *Channel) shutdown() {
	ch.mu.Lock()
	select {
	case <-ch.closed:
		ch.mu.Unlock()
		return
	default:
		close(ch.closed)
	}
	for id, h := range ch.handlers {
		delete(ch.handlers, id)
		close(h)
	}
	ch.mu.Unlock()
	_ = ch.Conn.Close()
}

func (ch *Channel) Close() error {
	return ch.Conn.Close()
}

func (ch *Channel) Closed() <-chan struct{} { return ch.closed }

func (ch *Channel) Err() error {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.closeErr
}

func PickCircID(used map[uint32]struct{}) (uint32, error) {
	for i := 0; i < 64; i++ {
		var b [4]byte
		if _, err := io.ReadFull(randReader(), b[:]); err != nil {
			return 0, err
		}
		id := binaryBE(b[:]) | 0x80000000
		if id == 0 {
			continue
		}
		if _, ok := used[id]; !ok {
			return id, nil
		}
	}
	return 0, fmt.Errorf("unable to allocate circid")
}

func binaryBE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
