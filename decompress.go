package dns

import (
	"bytes"
	"encoding/binary"
)

func decompress(b []byte, off int) (string, int) {
	buf := bytes.NewBuffer(nil)
	off0 := off
	for {
		c := b[off]
		if c >= 0xc0 { // TODO: handle 01 and 10 bits cases
			// technically offset is uint14 value
			// But message won't be longer than 512...
			offset := binary.BigEndian.Uint16([]byte{c ^ 0xc0, b[off+1]})
			off++
			s, _ := decompress(b, int(offset))
			buf.WriteString(s)
			break
		} else {
			if c == 0x0 {
				off++
				break
			}
			l := int(b[off])
			off++
			buf.Write(b[off : off+l])
			off += l
			buf.WriteString(".")
		}
	}
	return buf.String(), off - off0
}
