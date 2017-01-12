package dns

import (
	"bytes"
	"encoding/binary"
)

// decompress implements RFC 1035: 4.1.4. Message compression"
// which follows the pointer of offsets until it finds 0x0.
// It returns labels as string and length of bytes read as int
func decompress(b []byte, off int) (string, int) {
	buf := bytes.NewBuffer(nil)
	off0 := off
	for {
		c := b[off]
		off++
		if c >= 0xc0 { // TODO: handle 01 and 10 bits cases
			// technically offset is uint14 value
			// But message won't be longer than 512...
			offset := binary.BigEndian.Uint16([]byte{c ^ 0xc0, b[off]})
			s, _ := decompress(b, int(offset))
			buf.WriteString(s)
			off++
			break
		} else {
			if c == 0x0 {
				break
			}
			l := int(c)
			buf.Write(b[off : off+l])
			off += l
			buf.WriteString(".")
		}
	}
	return buf.String(), off - off0
}
