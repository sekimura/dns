package dns

import "encoding/binary"

func Unpack(b []byte) (*Message, error) {
	m := new(Message)

	m.Header.ID = binary.BigEndian.Uint16(b[0:2])
	m.Header.Flags = binary.BigEndian.Uint16(b[2:4])
	m.Header.QDcount = binary.BigEndian.Uint16(b[4:6])
	m.Header.ANcount = binary.BigEndian.Uint16(b[6:8])
	m.Header.NScount = binary.BigEndian.Uint16(b[8:10])
	m.Header.ARcount = binary.BigEndian.Uint16(b[10:12])

	off := 12
	qname, n := decompress(b, 12)
	m.QName = qname
	off += n

	m.Qtype = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	m.Qclass = binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	m.Answer = make([]RR, int(m.Header.ANcount))
	for i := 0; i < int(m.Header.ANcount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Answer[i] = rr
		off += n
	}

	m.Authority = make([]RR, int(m.Header.NScount))
	for i := 0; i < int(m.Header.NScount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Authority[i] = rr
		off += n
	}

	m.Additional = make([]RR, int(m.Header.ARcount))
	for i := 0; i < int(m.Header.ARcount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Additional[i] = rr
		off += n
	}

	return m, nil
}

func unpackRR(b []byte, off int, rr *RR) int {
	name, _ := decompress(b, off)
	rr.Name = name

	rr.Type = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	rr.Class = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	rr.TTL = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	rr.RDLength = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	rr.RData = b[off : off+int(rr.RDLength)]

	return 10 + int(rr.RDLength)
}
