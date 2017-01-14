package dns

import (
	"encoding/binary"
	"net"
)

func Unpack(b []byte) (*Message, error) {
	m := new(Message)

	m.ID = binary.BigEndian.Uint16(b[0:2])
	m.Flags = binary.BigEndian.Uint16(b[2:4])
	m.QDcount = binary.BigEndian.Uint16(b[4:6])
	m.ANcount = binary.BigEndian.Uint16(b[6:8])
	m.NScount = binary.BigEndian.Uint16(b[8:10])
	m.ARcount = binary.BigEndian.Uint16(b[10:12])

	off := 12

	m.Question = make([]Q, int(m.QDcount))
	for i := 0; i < len(m.Question); i++ {
		qname, n := decompress(b, off)
		off += n

		qtype := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		qclass := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		m.Question[i] = Q{Name: qname, Type: qtype, Class: qclass}
	}

	m.Answer = make([]RR, int(m.ANcount))
	for i := 0; i < int(m.ANcount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Answer[i] = rr
		off += n
	}

	m.Authority = make([]RR, int(m.NScount))
	for i := 0; i < int(m.NScount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Authority[i] = rr
		off += n
	}

	m.Additional = make([]RR, int(m.ARcount))
	for i := 0; i < int(m.ARcount); i++ {
		rr := RR{}
		n := unpackRR(b, off, &rr)
		m.Additional[i] = rr
		off += n
	}

	return m, nil
}

func unpackRR(b []byte, off int, rr *RR) int {
	off0 := off
	name, n := decompress(b, off)
	rr.Name = name
	off += n

	rr.Type = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	rr.Class = binary.BigEndian.Uint16(b[off : off+2])
	off += 2
	rr.TTL = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	rr.RDLength = binary.BigEndian.Uint16(b[off : off+2])
	off += 2

	switch rr.Type {
	case QtypeCNAME:
		name, _ := decompress(b, off)
		rr.RData = name
	case QtypeA:
		rr.RData = net.IP(b[off : off+int(rr.RDLength)])
	case QtypeAAAA:
		rr.RData = net.IP(b[off : off+int(rr.RDLength)])
	default:
		rr.RData = b[off : off+int(rr.RDLength)]
	}

	off += int(rr.RDLength)

	return off - off0
}
