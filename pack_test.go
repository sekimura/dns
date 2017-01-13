package dns

import (
	"encoding/binary"
	"testing"
)

func TestPack(t *testing.T) {
	m := &Message{
		QName:  "www.sekimura.org.",
		Qtype:  QtypeA,
		Qclass: QclassIN,
	}
	b, err := Pack(m)
	if err != nil {
		t.Error(err)
	}
	if b[12] != 0x3 || string(b[13:16]) != "www" {
		t.Error("the first label did not match")
	}
	if b[16] != 0x8 || string(b[17:25]) != "sekimura" {
		t.Error("the second label did not match")
	}
	if b[25] != 0x3 || string(b[26:29]) != "org" {
		t.Error("the third label did not match")
	}
	if b[29] != 0x0 {
		t.Error("missing the termination")
	}
	if QtypeA != binary.BigEndian.Uint16(b[30:32]) {
		t.Errorf("Qtype did not match")
	}
	if QclassIN != binary.BigEndian.Uint16(b[32:34]) {
		t.Error("Qclass did not match")
	}
}
