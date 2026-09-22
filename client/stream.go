package client

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adam/gotor/cell"
)

var ErrOnion = errors.New("onion services are not implemented")

type Stream struct {
	id   uint16
	circ *Circuit

	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	err    error
	closed atomic.Bool
	pack   int
	deliv  int
}

func (s *Stream) deliver(msg *cell.Relay) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch msg.Command {
	case cell.RelayData:
		s.buf = append(s.buf, msg.Data...)
		s.cond.Broadcast()
	case cell.RelayEnd, cell.RelayConnected:
		if msg.Command == cell.RelayEnd {
			s.closed.Store(true)
			s.err = io.EOF
			s.cond.Broadcast()
			s.circ.flowMu.Lock()
			s.circ.flowCond.Broadcast()
			s.circ.flowMu.Unlock()
		}
	}
}

func (circ *Circuit) Dial(host string, port uint16) (*Stream, error) {
	return circ.DialFlags(host, port, 0)
}

func (circ *Circuit) DialFlags(host string, port uint16, flags uint32) (*Stream, error) {
	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		return nil, ErrOnion
	}
	circ.mu.Lock()
	sid := circ.nextSID
	circ.nextSID++
	if circ.nextSID == 0 {
		circ.nextSID = 1
	}
	wait := make(chan *cell.Relay, 4)
	circ.waiters[sid] = wait
	circ.mu.Unlock()

	s := &Stream{id: sid, circ: circ, pack: cell.StreamWindowStart, deliv: cell.StreamWindowStart}
	s.cond = sync.NewCond(&s.mu)
	circ.mu.Lock()
	circ.streams[sid] = s
	circ.mu.Unlock()

	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command:  cell.RelayBegin,
		StreamID: sid,
		Data:     cell.BeginPayloadFlags(host, port, flags),
	}); err != nil {
		return nil, err
	}
	return circ.waitConnected(s, wait)
}

func (circ *Circuit) DialDir() (*Stream, error) {
	circ.mu.Lock()
	sid := circ.nextSID
	circ.nextSID++
	if circ.nextSID == 0 {
		circ.nextSID = 1
	}
	wait := make(chan *cell.Relay, 4)
	circ.waiters[sid] = wait
	circ.mu.Unlock()
	s := &Stream{id: sid, circ: circ, pack: cell.StreamWindowStart, deliv: cell.StreamWindowStart}
	s.cond = sync.NewCond(&s.mu)
	circ.mu.Lock()
	circ.streams[sid] = s
	circ.mu.Unlock()
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command:  cell.RelayBeginDir,
		StreamID: sid,
	}); err != nil {
		return nil, err
	}
	return circ.waitConnected(s, wait)
}

func (circ *Circuit) waitConnected(s *Stream, wait <-chan *cell.Relay) (*Stream, error) {
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	select {
	case msg := <-wait:
		if msg.Command == cell.RelayEnd {
			reason := byte(cell.EndReasonMisc)
			if len(msg.Data) > 0 {
				reason = msg.Data[0]
			}
			return nil, cell.EndError{Reason: reason}
		}
		if msg.Command != cell.RelayConnected {
			return nil, fmt.Errorf("expected CONNECTED, got %d", msg.Command)
		}
	case <-circ.done:
		circ.mu.Lock()
		err := circ.dead
		circ.mu.Unlock()
		if err == nil {
			err = cell.DestroyError{Reason: cell.DestroyChannelClosed}
		}
		return nil, err
	case <-t.C:
		return nil, fmt.Errorf("timeout waiting for CONNECTED")
	}
	circ.mu.Lock()
	delete(circ.waiters, s.id)
	circ.streams[s.id] = s
	circ.mu.Unlock()
	return s, nil
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) == 0 && !s.closed.Load() && s.err == nil {
		s.cond.Wait()
	}
	if len(s.buf) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	sent := 0

	for len(p) > 0 {
		n := cell.MaxRelayData
		if n > len(p) {
			n = len(p)
		}
		if err := s.circ.takePackage(s); err != nil {
			return sent, err
		}
		if err := s.circ.sendRelay(len(s.circ.hops)-1, cell.CmdRelay, cell.Relay{
			Command:  cell.RelayData,
			StreamID: s.id,
			Data:     p[:n],
		}); err != nil {
			return sent, err
		}
		p = p[n:]
		sent += n
	}
	return sent, nil
}

func (s *Stream) Close() error {
	_ = s.circ.sendRelay(len(s.circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command:  cell.RelayEnd,
		StreamID: s.id,
		Data:     []byte{cell.EndReasonDone},
	})
	s.closed.Store(true)
	s.mu.Lock()
	s.cond.Broadcast()
	s.mu.Unlock()
	s.circ.flowMu.Lock()
	s.circ.flowCond.Broadcast()
	s.circ.flowMu.Unlock()
	s.circ.mu.Lock()
	delete(s.circ.streams, s.id)
	s.circ.mu.Unlock()
	return nil
}
