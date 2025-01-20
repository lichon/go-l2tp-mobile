package l2tp

import "fmt"

type pppProtocolType uint16

const (
	PPPAddress      byte            = 0xFF
	PPPControl      byte            = 0x03
	PPPProtocolIP   pppProtocolType = 0x0021
	PPPProtocolLCP  pppProtocolType = 0xC021
	PPPProtocolPAP  pppProtocolType = 0x0023
	PPPProtocolPPCP pppProtocolType = 0x8021
)

// PPP header
type pppHeader struct {
	address  byte
	control  byte
	protocol pppProtocolType
}

type pppPayload []byte

// ppp represents a single PPP frame
type ppp struct {
	header  pppHeader
	payload pppPayload
}

var _ fmt.Stringer = (*ppp)(nil)

func (p ppp) String() string {
	return fmt.Sprintf("%s %s", p.header, p.payload)
}

var _ fmt.Stringer = (*pppHeader)(nil)

func (hdr pppHeader) String() string {
	return fmt.Sprintf("Address: %x, Control: %x, Protocol: %x", hdr.address, hdr.control, hdr.protocol)
}

// newPPPHeader creates a new PPP header
func newPPPHeader(protocol pppProtocolType) *pppHeader {
	return &pppHeader{
		address:  PPPAddress,
		control:  PPPControl,
		protocol: protocol,
	}
}

// newPPP creates a new PPP frame
func newPPP(protocol pppProtocolType, data []byte) *ppp {
	return &ppp{
		header:  *newPPPHeader(protocol),
		payload: data,
	}
}

// getType returns the protocol type for the PPP frame.
func (p *ppp) getType() pppProtocolType {
	return p.header.protocol
}

// rawData returns the data type for the PPP payload, along with the raw byte
// slice for the data carried by the PPP frame.
func (p *ppp) rawData() (protocol pppProtocolType, buffer []byte) {
	return p.header.protocol, p.payload
}

type lcpHeader struct {
	code   byte
	ident  byte
	length uint16
}

func newPPPLCP() *ppp {
	return newPPP(PPPProtocolLCP, nil)
}
