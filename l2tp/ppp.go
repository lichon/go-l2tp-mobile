package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var pppLCPId = 0

type pppProtocolType uint16

const (
	pppHeaderLen         = 4
	pppProtocolHeaderLen = 4
)

const (
	pppAddress      byte            = 0xFF
	pppControl      byte            = 0x03
	pppProtocolIP4  pppProtocolType = 0x0021
	pppProtocolLCP  pppProtocolType = 0xC021
	pppProtocolPAP  pppProtocolType = 0x0023
	pppProtocolPPCP pppProtocolType = 0x8021
)

const (
	pppLCPCodeConfigureRequest byte = 0x01
	pppLCPCodeConfigureAck     byte = 0x02
	pppLCPCodeConfigureNak     byte = 0x03
	pppLCPCodeConfigureReject  byte = 0x04
	pppLCPCodeTerminateRequest byte = 0x05
	pppLCPCodeTerminateAck     byte = 0x06
	pppLCPCodeCodeReject       byte = 0x07
	pppLCPCodeProtocolReject   byte = 0x08
	pppLCPCodeEchoRequest      byte = 0x09
	pppLCPCodeEchoReply        byte = 0x0A
	pppLCPCodeDiscardRequest   byte = 0x0B
)

const (
	pppPAPCodeAuthenticateRequest byte = 0x01
	pppPAPCodeAuthenticateAck     byte = 0x02
	pppPAPCodeAuthenticateNak     byte = 0x03
)

const (
	pppLPCPCodeConfigureRequest byte = 0x01
	pppLPCPCodeConfigureAck     byte = 0x02
	pppLPCPCodeConfigureNak     byte = 0x03
	pppLPCPCodeConfigureReject  byte = 0x04
	pppLPCPCodeTerminateRequest byte = 0x05
	pppLPCPCodeTerminateAck     byte = 0x06
	pppLPCPCodeCodeReject       byte = 0x07
	pppLPCPCodeProtocolReject   byte = 0x08
	pppLPCPCodeEchoRequest      byte = 0x09
	pppLPCPCodeEchoReply        byte = 0x0A
	pppLPCPCodeDiscardRequest   byte = 0x0B
)

const (
	pppIP4CodeConfigureRequest byte = 0x01
	pppIP4CodeConfigureAck     byte = 0x02
	pppIP4CodeConfigureNak     byte = 0x03
	pppIP4CodeConfigureReject  byte = 0x04
	pppIP4CodeTerminateRequest byte = 0x05
	pppIP4CodeTerminateAck     byte = 0x06
	pppIP4CodeCodeReject       byte = 0x07
	pppIP4CodeProtocolReject   byte = 0x08
	pppIP4CodeEchoRequest      byte = 0x09
	pppIP4CodeEchoReply        byte = 0x0A
	pppIP4CodeDiscardRequest   byte = 0x0B
)

// PPP header
type pppHeader struct {
	address  byte
	control  byte
	protocol pppProtocolType
}

type pppPayload struct {
	code       byte
	identifier byte
	length     uint16
	data       []byte
}

// ppp represents a single PPP frame
type ppp struct {
	header  pppHeader
	payload pppPayload
}

// getType returns the protocol type for the PPP frame.
func (p *ppp) getProtocol() pppProtocolType {
	return p.header.protocol
}

func parsePPPBuffer(b []byte) (p *ppp, err error) {
	if len(b) <= pppHeaderLen {
		return nil, errors.New("no PPP present in the input buffer")
	}
	return &ppp{
		header: pppHeader{
			address:  b[0],
			control:  b[1],
			protocol: pppProtocolType(binary.BigEndian.Uint16(b[2:4])),
		},
		payload: pppPayload{
			code:       b[4],
			identifier: b[5],
			length:     binary.BigEndian.Uint16(b[6:8]),
			data:       b[8:],
		},
	}, nil
}

// newPPPHeader creates a new PPP header
func newPPPHeader(protocol pppProtocolType) *pppHeader {
	return &pppHeader{
		address:  pppAddress,
		control:  pppControl,
		protocol: protocol,
	}
}

func newPPPPayload(code byte, identifier byte, data []byte) *pppPayload {
	return &pppPayload{
		code:       code,
		identifier: identifier,
		length:     uint16(len(data)),
		data:       data,
	}
}

// newPPP creates a new PPP frame
func newPPP(protocol pppProtocolType, payload *pppPayload) *ppp {
	return &ppp{
		header:  *newPPPHeader(protocol),
		payload: *payload,
	}
}

func getLCPId() byte {
	pppLCPId++
	return byte(pppLCPId)
}

type pppOption struct {
	type_  byte
	length byte
	value  []byte
}

func encodePPPOptions(opts []pppOption) []byte {
	encBuf := new(bytes.Buffer)
	for _, o := range opts {
		err := binary.Write(encBuf, binary.BigEndian, o)
		if err != nil {
			return nil
		}
	}
	return encBuf.Bytes()
}

func newPPPLCPReq(opts []pppOption) *ppp {
	return newPPP(
		pppProtocolLCP,
		newPPPPayload(pppLCPCodeConfigureRequest, getLCPId(), encodePPPOptions(opts)),
	)
}

func newPPPLCPAck(lcpId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolLCP,
		newPPPPayload(pppLCPCodeConfigureAck, lcpId, encodePPPOptions(opts)),
	)
}

func newPPPLCPRej(lcpId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolLCP,
		newPPPPayload(pppLCPCodeConfigureReject, lcpId, encodePPPOptions(opts)),
	)
}

type papRequest struct {
	peerIdLength   byte
	peerId         string
	passwordLength byte
	password       string
}

func (pap *papRequest) encode() []byte {
	encBuf := new(bytes.Buffer)
	err := binary.Write(encBuf, binary.BigEndian, pap)
	if err != nil {
		return nil
	}
	return encBuf.Bytes()
}

func newPPPPapReq(peerId string, password string) *ppp {
	return newPPP(
		pppProtocolPAP,
		newPPPPayload(pppPAPCodeAuthenticateRequest, getLCPId(), (&papRequest{
			peerIdLength:   byte(len(peerId)),
			peerId:         peerId,
			passwordLength: byte(len(password)),
			password:       password,
		}).encode()),
	)
}
