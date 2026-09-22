package client

import (
	"fmt"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/crypto"
)

func (circ *Circuit) EstablishRendezvous(cookie []byte) error {
	if len(cookie) != 20 {
		return fmt.Errorf("rendezvous cookie")
	}
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayEstablishRendezvous,
		Data:    append([]byte(nil), cookie...),
	}); err != nil {
		return err
	}
	_, err := circ.waitCtrl(cell.RelayRendezvousEstablished, 10*time.Second)
	return err
}

func (circ *Circuit) Rendezvous1(cookie, handshake []byte) error {
	data := append(append([]byte(nil), cookie...), handshake...)
	return circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayRendezvous1,
		Data:    data,
	})
}

func (circ *Circuit) WaitRendezvous2(st *crypto.HSNtorClient) error {
	msg, err := circ.waitCtrl(cell.RelayRendezvous2, 10*time.Second)
	if err != nil {
		return err
	}
	keys, err := st.Finish(msg.Data)
	if err != nil {
		return err
	}
	hop, err := crypto.NewHopHS(keys)
	if err != nil {
		return err
	}
	circ.hops = append(circ.hops, hop)
	return nil
}

func (circ *Circuit) AttachHSHop(keys *crypto.CircuitKeys) error {
	if keys == nil {
		return fmt.Errorf("nil hs keys")
	}
	swapped := &crypto.CircuitKeys{
		Df: keys.Db,
		Db: keys.Df,
		Kf: keys.Kb,
		Kb: keys.Kf,
		KH: keys.KH,
	}
	hop, err := crypto.NewHopHS(swapped)
	if err != nil {
		return err
	}
	circ.hops = append(circ.hops, hop)
	return nil
}

func (circ *Circuit) RendData(b []byte) error {
	return circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayData,
		Data:    b,
	})
}

func (circ *Circuit) WaitRendData() ([]byte, error) {
	msg, err := circ.waitCtrl(cell.RelayData, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return msg.Data, nil
}
