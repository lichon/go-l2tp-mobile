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
	pppProtocolIPV4 pppProtocolType = 0x0021
	pppProtocolLCP  pppProtocolType = 0xC021
	pppProtocolPAP  pppProtocolType = 0x0023
	pppProtocolIPCP pppProtocolType = 0x8021
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

const (
	pppIP4OptionIPCompression byte = 0x002D
	pppIP4OptionIPAddress     byte = 0x03
	pppIP4OptionPrimaryDNS    byte = 0x81
	pppIP4OptionSecondaryDNS  byte = 0x83
)

const (
	pppLCPOptionMRU          byte = 0x01
	pppLCPOptionAuthProtocol byte = 0x03
	pppLCPOptionMagicNumber  byte = 0x05
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

func (p *ppp) getPayload() []byte {
	return p.payload.data
}

func (p *ppp) isProtocolType(pt pppProtocolType) bool {
	return p.header.protocol == pt
}

func (p *ppp) validate() error {
	if p.header.address == pppAddress && p.header.control == pppControl {
		return nil
	}
	return errors.New("invalid PPP header")
}

func (payload *pppPayload) getOptions() []pppOption {
	opts := make([]pppOption, 0)
	buf := bytes.NewBuffer(payload.data)
	for buf.Len() > 0 {
		var opt pppOption
		err := binary.Read(buf, binary.BigEndian, &opt)
		if err != nil {
			return nil
		}
		opts = append(opts, opt)
	}
	return opts
}

func (payload *pppPayload) getOptionValue(optType byte) []byte {
	opts := payload.getOptions()
	for _, opt := range opts {
		if opt.type_ == optType {
			return opt.value
		}
	}
	return nil
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

func newPPPLCPAck(reqId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolLCP,
		newPPPPayload(pppLCPCodeConfigureAck, reqId, encodePPPOptions(opts)),
	)
}

func newPPPLCPRej(reqId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolLCP,
		newPPPPayload(pppLCPCodeConfigureReject, reqId, encodePPPOptions(opts)),
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

func newPPPPapAck(reqId byte) *ppp {
	return newPPP(
		pppProtocolPAP,
		newPPPPayload(pppPAPCodeAuthenticateAck, reqId, []byte{}),
	)
}

func newPPPIpcpReq(opts []pppOption) *ppp {
	return newPPP(
		pppProtocolIPCP,
		newPPPPayload(pppIP4CodeConfigureRequest, getLCPId(), encodePPPOptions(opts)),
	)
}

func newPPPIpcpAck(reqId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolIPCP,
		newPPPPayload(pppIP4CodeConfigureAck, reqId, encodePPPOptions(opts)),
	)
}

func newPPPIpcpRej(reqId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolIPCP,
		newPPPPayload(pppIP4CodeConfigureReject, reqId, encodePPPOptions(opts)),
	)
}

func newPPPIpcpNak(reqId byte, opts []pppOption) *ppp {
	return newPPP(
		pppProtocolIPCP,
		newPPPPayload(pppIP4CodeConfigureNak, reqId, encodePPPOptions(opts)),
	)
}

// L2TPv2 and L2TPv3 headers have these fields in common
type l2tpDataHeader struct {
	FlagsVer uint16
	Tid      uint16
	Sid      uint16
}

// pppDataMessage represents an data message
type pppDataMessage struct {
	header  l2tpDataHeader
	payload []byte
	ppp     *ppp
	// implement controlMessage interface
	controlMessage
}

func parsePPPMessage(b []byte) (messages []controlMessage) {
	var msg *pppDataMessage
	var err error
	if msg, err = bytesToDataMsg(b); err != nil {
		return nil
	}
	if msg.ppp, err = parsePPPBuffer(msg.payload); err != nil {
		return nil
	}
	return []controlMessage{msg}
}

func (m *pppDataMessage) protocolVersion() ProtocolVersion {
	return ProtocolVersion(2)
}

func (m *pppDataMessage) getLen() int {
	return int(v2DataHeaderLen + len(m.payload)) // 6 bytes for the header
}

func (m *pppDataMessage) ns() uint16 {
	// Assuming Ns is not used in data messages, return 0
	return 0
}

func (m *pppDataMessage) nr() uint16 {
	// Assuming Nr is not used in data messages, return 0
	return 0
}

func (m *pppDataMessage) getAvps() []avp {
	// Data messages do not have AVPs, return an empty slice
	return []avp{}
}

func (m *pppDataMessage) getType() avpMsgType {
	// Data messages do not have a Message Type AVP, return a default value
	return avpMsgType(0)
}

func (m *pppDataMessage) appendAvp(avp *avp) {
	// Data messages do not support AVPs, do nothing
}

func (m *pppDataMessage) setTransportSeqNum(ns, nr uint16) {
	// Data messages do not use transport sequence numbers, do nothing
}

func (m *pppDataMessage) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, m.header); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, m.payload); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (m *pppDataMessage) validate() error {
	if m.ppp == nil {
		return errors.New("no PPP frame present in the data message")
	}
	return m.ppp.validate()
}

func (m *pppDataMessage) Tid() uint16 {
	return m.header.Tid
}

func (m *pppDataMessage) Sid() uint16 {
	return m.header.Sid
}

func (m *pppDataMessage) Protocol() pppProtocolType {
	return m.ppp.getProtocol()
}

func newPPPDataMessage(tid ControlConnID, sid ControlConnID, data []byte) (msg *pppDataMessage, err error) {
	return &pppDataMessage{
		header: l2tpDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
		},
		payload: data,
	}, nil
}

func bytesToDataMsg(b []byte) (msg *pppDataMessage, err error) {
	var hdr l2tpDataHeader

	r := bytes.NewReader(b)
	if err = binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	return &pppDataMessage{
		header:  hdr,
		payload: b[v2DataHeaderLen:],
	}, nil
}
