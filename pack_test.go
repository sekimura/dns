package dns

import "testing"

func TestPack(t *testing.T) {
	m := &Message{
		QName:  "www.sekimura.org.",
		Qtype:  QtypeA,
		Qclass: QclassIN,
	}
	_, err := Pack(m)
	if err != nil {
		t.Error(err)
	}
}
