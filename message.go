package dns

type Message struct {
	Header     Header
	QName      string
	Qtype      uint16
	Qclass     uint16
	Answer     []RR
	Authority  []RR
	Additional []RR
}

type Header struct {
	ID      uint16
	Flags   uint16
	QDcount uint16
	ANcount uint16
	NScount uint16
	ARcount uint16
}

type RR struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

const (
	QtypeA     uint16 = 0x1
	QtypeAAAA         = 0x5
	QtypeCNAME        = 0x1c

	QclassIN uint16 = 0x1
)
