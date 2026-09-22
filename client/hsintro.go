package client

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/crypto"
)

type Introduced struct {
	Cookie   []byte
	OnionKey []byte
	Address  net.IP
	ORPort   uint16
	Server   *crypto.HSNtorServer
}

func (circ *Circuit) EstablishIntro(auth ed25519.PrivateKey) error {
	return circ.establishIntro(auth, false)
}

func (circ *Circuit) EstablishIntroCorruptMAC(auth ed25519.PrivateKey) error {
	return circ.establishIntro(auth, true)
}

func (circ *Circuit) establishIntro(auth ed25519.PrivateKey, corruptMAC bool) error {
	if len(circ.hops) == 0 {
		return fmt.Errorf("no hops")
	}
	authPub := auth.Public().(ed25519.PublicKey)
	prefix := cell.EstablishIntroMACPrefix(authPub)
	mac := crypto.IntroHandshakeMAC(circ.hops[len(circ.hops)-1].KH(), prefix)
	if corruptMAC && len(mac) > 0 {
		mac[0] ^= 0xff
	}
	signed := append(append([]byte(nil), prefix...), mac...)
	sig := ed25519.Sign(auth, append([]byte("Tor establish-intro cell v1"), signed...))
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayEstablishIntro,
		Data:    cell.EncodeEstablishIntro(authPub, mac, sig),
	}); err != nil {
		return err
	}
	msg, err := circ.waitCtrl(cell.RelayIntroEstablished, 10*time.Second)
	if err != nil {
		return err
	}
	if msg.Command != cell.RelayIntroEstablished {
		return fmt.Errorf("expected INTRO_ESTABLISHED, got %d", msg.Command)
	}
	return nil
}

func (circ *Circuit) Introduce1(authKey, encPub, subcred, cookie, onionKey []byte) error {
	var ipv4 [4]byte
	pt := cell.EncodeIntroPlaintext(cookie, onionKey, ipv4, 9001)
	enc, err := crypto.IntroduceEncrypt(encPub, authKey, subcred, pt)
	if err != nil {
		return err
	}
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayIntroduce1,
		Data:    cell.EncodeIntroduce1(authKey, enc),
	}); err != nil {
		return err
	}
	msg, err := circ.waitCtrl(cell.RelayIntroduceAck, 10*time.Second)
	if err != nil {
		return err
	}
	st, err := cell.ParseIntroduceAck(msg.Data)
	if err != nil {
		return err
	}
	if st != 0 {
		return fmt.Errorf("INTRODUCE_ACK status %d", st)
	}
	return nil
}

func (circ *Circuit) WaitIntroduce2(encPriv, authKey, subcred []byte) (*Introduced, error) {
	msg, err := circ.waitCtrl(cell.RelayIntroduce2, 10*time.Second)
	if err != nil {
		return nil, err
	}
	_, encrypted, err := cell.ParseIntroduce1(msg.Data)
	if err != nil {
		return nil, err
	}
	pt, srv, err := crypto.IntroduceDecryptServer(encPriv, authKey, subcred, encrypted)
	if err != nil {
		return nil, err
	}
	cookie, onion, ip, port, err := cell.ParseIntroRendezvous(pt)
	if err != nil {
		return nil, err
	}
	return &Introduced{
		Cookie:   cookie,
		OnionKey: onion,
		Address:  net.IP(append([]byte(nil), ip[:]...)),
		ORPort:   port,
		Server:   srv,
	}, nil
}

func (circ *Circuit) waitCtrl(cmd byte, d time.Duration) (*cell.Relay, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case msg := <-circ.ctrl:
			if msg.Command == cmd {
				return msg, nil
			}
		case <-circ.done:
			circ.mu.Lock()
			err := circ.dead
			circ.mu.Unlock()
			if err == nil {
				err = fmt.Errorf("circuit dead")
			}
			return nil, err
		case <-t.C:
			return nil, fmt.Errorf("timeout waiting for relay cmd %d", cmd)
		}
	}
}
