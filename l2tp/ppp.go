package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var pppLCPId = 0

type pppProtocolType uint16

const pppLCPMagicNumber uint32 = 0x12345678

const (
	pppDataHeaderLen     = 10
	pppPayloadHeaderLen  = 4
	pppProtocolHeaderLen = 4
)

const (
	pppAddress      byte            = 0xFF
	pppControl      byte            = 0x03
	pppProtocolIPV4 pppProtocolType = 0x0021
	pppProtocolLCP  pppProtocolType = 0xC021
	pppProtocolPAP  pppProtocolType = 0xC023
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

type pppPayload struct {
	code       byte
	identifier byte
	length     uint16
	data       []byte
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

func newPPPPayload(code byte, identifier byte, data []byte) *pppPayload {
	return &pppPayload{
		code:       code,
		identifier: identifier,
		length:     uint16(len(data)),
		data:       data,
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

func (opt *pppOption) toUint16() uint16 {
	return binary.BigEndian.Uint16(opt.value)
}

func (opt *pppOption) toUint32() uint32 {
	return binary.BigEndian.Uint32(opt.value)
}

func (opt *pppOption) supportPap() bool {
	return opt.type_ == pppLCPOptionAuthProtocol && pppProtocolType(opt.toUint16()) == pppProtocolPAP
}

func (opt *pppOption) supportMagicNumber() bool {
	return opt.type_ == pppLCPOptionMagicNumber
}

func (opt *pppOption) supportMRU() bool {
	return opt.type_ == pppLCPOptionMRU
}

func newPPPResponse(tid, sid ControlConnID, request *pppDataMessage) *pppDataMessage {
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			protocol: request.header.protocol,
		},
		payload: pppPayload{
			code:       request.payload.code + 1,
			identifier: request.payload.identifier,
			length:     uint16(len(request.payload.data)),
			data:       request.payload.data,
		},
	}
}

func newPPPMessage(tid, sid ControlConnID, protocol pppProtocolType, code, reqId byte, opts []pppOption) *pppDataMessage {
	optsBytes := encodePPPOptions(opts)
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			protocol: protocol,
		},
		payload: pppPayload{
			code:       code,
			identifier: reqId,
			length:     uint16(len(optsBytes)),
			data:       optsBytes,
		},
	}
}

func newPapRequest(tid, sid ControlConnID, peerId, password string) *pppDataMessage {
	papRequest := &papRequest{
		peerIdLength:   byte(len(peerId)),
		peerId:         peerId,
		passwordLength: byte(len(password)),
		password:       password,
	}
	papBytes := papRequest.toBytes()
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			protocol: pppProtocolPAP,
		},
		payload: pppPayload{
			code:       pppPAPCodeAuthenticateRequest,
			identifier: getLCPId(),
			length:     uint16(len(papBytes)),
			data:       papBytes,
		},
	}
}

type papRequest struct {
	peerIdLength   byte
	peerId         string
	passwordLength byte
	password       string
}

func (pap *papRequest) toBytes() []byte {
	encBuf := new(bytes.Buffer)
	err := binary.Write(encBuf, binary.BigEndian, pap)
	if err != nil {
		return nil
	}
	return encBuf.Bytes()
}

type PPPDataHeader struct {
	// L2TP header
	FlagsVer uint16
	Tid      uint16
	Sid      uint16
	// PPP header
	Address  byte
	Control  byte
	protocol pppProtocolType
}

func NewPPPDataHeader(tid, sid ControlConnID, protocol uint16) *PPPDataHeader {
	return &PPPDataHeader{
		FlagsVer: 0x0002,
		Tid:      uint16(tid),
		Sid:      uint16(sid),
		Address:  pppAddress,
		Control:  pppControl,
		protocol: pppProtocolType(protocol),
	}
}

func (h *PPPDataHeader) ToBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h)
	return buf.Bytes()
}

// pppDataMessage represents an data message
type pppDataMessage struct {
	header  PPPDataHeader
	payload pppPayload
	// implement controlMessage interface
	controlMessage
}

func parsePPPMessage(b []byte) (messages []controlMessage) {
	var msg *pppDataMessage
	var err error
	if msg, err = bytesToDataMsg(b); err != nil {
		return nil
	}
	return []controlMessage{msg}
}

func (m *pppDataMessage) protocolVersion() ProtocolVersion {
	return ProtocolVersion(2)
}

func (m *pppDataMessage) getLen() int {
	return int(pppDataHeaderLen + pppPayloadHeaderLen + len(m.payload.data))
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
	return avpMsgTypeIllegal
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
	if m.header.Address == pppAddress && m.header.Control == pppControl {
		return nil
	}
	return errors.New("invalid PPP header")
}

func (m *pppDataMessage) Tid() uint16 {
	return m.header.Tid
}

func (m *pppDataMessage) Sid() uint16 {
	return m.header.Sid
}

func (m *pppDataMessage) Protocol() pppProtocolType {
	return m.header.protocol
}

func bytesToDataMsg(b []byte) (msg *pppDataMessage, err error) {
	buf := bytes.NewBuffer(b)
	msg = new(pppDataMessage)
	if err = binary.Read(buf, binary.BigEndian, &msg.header); err != nil {
		return nil, err
	}
	if msg.header.protocol == pppProtocolIPV4 {
		msg.payload.data = b[pppDataHeaderLen:]
		return msg, nil
	} else {
		err = parsePPPBuffer(b[pppDataHeaderLen:], &msg.payload)
	}
	return msg, err
}

func parsePPPBuffer(b []byte, p *pppPayload) (err error) {
	if len(b) <= pppPayloadHeaderLen {
		return errors.New("no PPP present in the input buffer")
	}
	p.code = b[0]
	p.identifier = b[1]
	p.length = binary.BigEndian.Uint16(b[2:4])
	p.data = b[4:p.length]
	return nil
}
