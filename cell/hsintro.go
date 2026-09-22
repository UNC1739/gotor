package cell

import (
	"encoding/binary"
	"fmt"
)

const (
	AuthKeyEd25519 = 0x02
	OnionKeyNtor   = 0x01
)

func EncodeEstablishIntro(authKey, mac, sig []byte) []byte {
	buf := make([]byte, 1+2+len(authKey)+1+len(mac)+2+len(sig))
	off := 0
	buf[off] = AuthKeyEd25519
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(len(authKey)))
	off += 2
	copy(buf[off:], authKey)
	off += len(authKey)
	buf[off] = 0
	off++
	copy(buf[off:], mac)
	off += len(mac)
	binary.BigEndian.PutUint16(buf[off:], uint16(len(sig)))
	off += 2
	copy(buf[off:], sig)
	return buf
}

func EstablishIntroMACPrefix(authKey []byte) []byte {
	buf := make([]byte, 1+2+len(authKey)+1)
	buf[0] = AuthKeyEd25519
	binary.BigEndian.PutUint16(buf[1:], uint16(len(authKey)))
	copy(buf[3:], authKey)
	buf[3+len(authKey)] = 0
	return buf
}

func ParseEstablishIntro(data []byte) (authKey, mac, signed, sig []byte, err error) {
	if len(data) < 1+2+1+2 {
		return nil, nil, nil, nil, fmt.Errorf("short ESTABLISH_INTRO")
	}
	if data[0] != AuthKeyEd25519 {
		return nil, nil, nil, nil, fmt.Errorf("ESTABLISH_INTRO key type")
	}
	kl := int(binary.BigEndian.Uint16(data[1:3]))
	off := 3
	if kl != 32 || off+kl+1 > len(data) {
		return nil, nil, nil, nil, fmt.Errorf("ESTABLISH_INTRO auth key")
	}
	authKey = append([]byte(nil), data[off:off+kl]...)
	off += kl
	if data[off] != 0 {
		return nil, nil, nil, nil, fmt.Errorf("ESTABLISH_INTRO extensions")
	}
	off++
	macStart := off
	if off+32+2 > len(data) {
		return nil, nil, nil, nil, fmt.Errorf("short ESTABLISH_INTRO mac")
	}
	mac = append([]byte(nil), data[off:off+32]...)
	off += 32
	sl := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if sl != 64 || off+sl > len(data) {
		return nil, nil, nil, nil, fmt.Errorf("ESTABLISH_INTRO sig")
	}
	sig = append([]byte(nil), data[off:off+sl]...)
	signed = append([]byte(nil), data[:macStart+32]...)
	return authKey, mac, signed, sig, nil
}

func EncodeIntroduce1(authKey, encrypted []byte) []byte {
	buf := make([]byte, 20+1+2+len(authKey)+1+len(encrypted))
	off := 20
	buf[off] = AuthKeyEd25519
	off++
	binary.BigEndian.PutUint16(buf[off:], uint16(len(authKey)))
	off += 2
	copy(buf[off:], authKey)
	off += len(authKey)
	buf[off] = 0
	off++
	copy(buf[off:], encrypted)
	return buf
}

func ParseIntroduce1(data []byte) (authKey, encrypted []byte, err error) {
	if len(data) < 20+1+2+32+1 {
		return nil, nil, fmt.Errorf("short INTRODUCE1")
	}
	for i := 0; i < 20; i++ {
		if data[i] != 0 {
			return nil, nil, fmt.Errorf("legacy INTRODUCE1")
		}
	}
	if data[20] != AuthKeyEd25519 {
		return nil, nil, fmt.Errorf("INTRODUCE1 key type")
	}
	kl := int(binary.BigEndian.Uint16(data[21:23]))
	if kl != 32 || 23+kl+1 > len(data) {
		return nil, nil, fmt.Errorf("INTRODUCE1 auth key")
	}
	authKey = append([]byte(nil), data[23:23+kl]...)
	if data[23+kl] != 0 {
		return nil, nil, fmt.Errorf("INTRODUCE1 extensions")
	}
	encrypted = append([]byte(nil), data[23+kl+1:]...)
	return authKey, encrypted, nil
}

func EncodeIntroPlaintext(cookie, onionKey []byte, ipv4 [4]byte, port uint16) []byte {
	buf := make([]byte, 20+1+1+2+32+1+1+1+6)
	copy(buf, cookie)
	off := 20
	buf[off] = 0
	off++
	buf[off] = OnionKeyNtor
	off++
	binary.BigEndian.PutUint16(buf[off:], 32)
	off += 2
	copy(buf[off:], onionKey)
	off += 32
	buf[off] = 1
	off++
	buf[off] = LSIPv4
	off++
	buf[off] = 6
	off++
	copy(buf[off:], ipv4[:])
	off += 4
	binary.BigEndian.PutUint16(buf[off:], port)
	return buf
}

func ParseIntroPlaintext(pt []byte) (cookie, onionKey []byte, err error) {
	if len(pt) < 20+1+1+2+32 {
		return nil, nil, fmt.Errorf("short intro plaintext")
	}
	cookie = append([]byte(nil), pt[:20]...)
	off := 20
	nExt := int(pt[off])
	off++
	for i := 0; i < nExt; i++ {
		if off+2 > len(pt) {
			return nil, nil, fmt.Errorf("short intro ext")
		}
		off += 2 + int(pt[off+1])
	}
	if off+1+2+32 > len(pt) {
		return nil, nil, fmt.Errorf("short intro onion key")
	}
	if pt[off] != OnionKeyNtor {
		return nil, nil, fmt.Errorf("intro onion key type")
	}
	off++
	kl := int(binary.BigEndian.Uint16(pt[off:]))
	off += 2
	if kl != 32 || off+kl > len(pt) {
		return nil, nil, fmt.Errorf("intro onion key")
	}
	onionKey = append([]byte(nil), pt[off:off+kl]...)
	return cookie, onionKey, nil
}

func ParseIntroRendezvous(pt []byte) (cookie, onionKey []byte, ip [4]byte, port uint16, err error) {
	cookie, onionKey, err = ParseIntroPlaintext(pt)
	if err != nil {
		return nil, nil, ip, 0, err
	}
	off := 20 + 1 + 1 + 2 + 32
	if off+1+1+1+6 > len(pt) {
		return cookie, onionKey, ip, 0, nil
	}
	nspec := int(pt[off])
	off++
	for i := 0; i < nspec && off+2 <= len(pt); i++ {
		t := pt[off]
		l := int(pt[off+1])
		off += 2
		if off+l > len(pt) {
			break
		}
		if t == LSIPv4 && l == 6 {
			copy(ip[:], pt[off:off+4])
			port = binary.BigEndian.Uint16(pt[off+4 : off+6])
		}
		off += l
	}
	return cookie, onionKey, ip, port, nil
}

func EncodeIntroduceAck(status uint16) []byte {
	var b [3]byte
	binary.BigEndian.PutUint16(b[:2], status)
	return b[:]
}

func ParseIntroduceAck(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("short INTRODUCE_ACK")
	}
	return binary.BigEndian.Uint16(data[:2]), nil
}
