package dns

import "encoding/binary"

func Pack(m *Message) ([]byte, error) {
	b := [512]byte{}

	binary.BigEndian.PutUint16(b[0:2], m.ID)
	binary.BigEndian.PutUint16(b[2:4], m.Flags)
	binary.BigEndian.PutUint16(b[4:6], m.QDcount)
	binary.BigEndian.PutUint16(b[6:8], m.ANcount)
	binary.BigEndian.PutUint16(b[8:10], m.NScount)
	binary.BigEndian.PutUint16(b[10:12], m.ARcount)

	off := 12

	l := 0
	for i := 0; i < len(m.QName); i++ {
		if m.QName[i] == 0x2e { // "."
			b[off] = uint8(l)
			off++
			copy(b[off:off+l], m.QName[i-l:i])
			off += l
			l = 0
		} else {
			l++
		}
	}
	off++

	binary.BigEndian.PutUint16(b[off:off+2], m.Qtype)
	off += 2

	binary.BigEndian.PutUint16(b[off:off+2], m.Qclass)
	off += 2

	// TODO: support RRs
	return b[:off], nil
}
