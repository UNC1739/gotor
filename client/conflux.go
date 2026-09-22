package client

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/adam/gotor/cell"
)

func (circ *Circuit) owner() *Circuit {
	if circ.primary != nil {
		return circ.primary
	}
	return circ
}

func (circ *Circuit) ConfluxLink(other *Circuit) error {
	if other == nil || circ == other {
		return fmt.Errorf("need two distinct circuits")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	payload := cell.EncodeConfluxLink(cell.ConfluxLink{
		Version: cell.ConfluxVersion1,
		Nonce:   nonce,
		UX:      cell.ConfluxUXMinLatency,
	})
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayConfluxLink,
		Data:    payload,
	}); err != nil {
		return err
	}
	if err := other.sendRelay(len(other.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayConfluxLink,
		Data:    payload,
	}); err != nil {
		return err
	}
	msg, err := circ.waitCtrl(cell.RelayConfluxLinked, 15*time.Second)
	if err != nil {
		return fmt.Errorf("link primary: %w", err)
	}
	got, err := cell.ParseConfluxLink(msg.Data)
	if err != nil || got.Nonce != nonce {
		return fmt.Errorf("LINKED mismatch")
	}
	msg, err = other.waitCtrl(cell.RelayConfluxLinked, 15*time.Second)
	if err != nil {
		return fmt.Errorf("link secondary: %w", err)
	}
	got, err = cell.ParseConfluxLink(msg.Data)
	if err != nil || got.Nonce != nonce {
		return fmt.Errorf("LINKED mismatch")
	}
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{Command: cell.RelayConfluxLinkedAck}); err != nil {
		return err
	}
	if err := other.sendRelay(len(other.hops)-1, cell.CmdRelay, cell.Relay{Command: cell.RelayConfluxLinkedAck}); err != nil {
		return err
	}
	other.primary = circ
	return nil
}

func (circ *Circuit) ConfluxSwitch(seq uint32) error {
	return circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayConfluxSwitch,
		Data:    cell.EncodeConfluxSwitch(seq),
	})
}
