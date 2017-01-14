package dns

type Q struct {
	Name  string
	Type  uint16
	Class uint16
}

type Message struct {
	ID         uint16
	Flags      uint16
	QDcount    uint16
	ANcount    uint16
	NScount    uint16
	ARcount    uint16
	Question   []Q
	Answer     []RR
	Authority  []RR
	Additional []RR
}

type RR struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    interface{}
}

const (
	QtypeA     uint16 = 1
	QtypeNS           = 2
	QtypeCNAME        = 5
	QtypeSOA          = 6
	QtypeWKS          = 11
	QtypePTR          = 12
	QtypeMX           = 15
	QtypeSRV          = 33
	QtypeAAAA         = 28
	QtypeANY          = 255

	QclassIN uint16 = 0x1
)
