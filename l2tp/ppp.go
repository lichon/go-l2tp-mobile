package l2tp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var pppLCPId = 0

type pppProtocolType uint16

const pppLCPMagicNumber uint32 = 0x12345678
const pppLCPMRU uint16 = 1500

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
	pppCodeConfigureRequest byte = 0x01
	pppCodeConfigureAck     byte = 0x02
	pppCodeConfigureNak     byte = 0x03
	pppCodeConfigureReject  byte = 0x04
	pppCodeTerminateRequest byte = 0x05
	pppCodeTerminateAck     byte = 0x06
	pppCodeCodeReject       byte = 0x07
	pppCodeProtocolReject   byte = 0x08
	pppCodeEchoRequest      byte = 0x09
	pppCodeEchoReply        byte = 0x0A
	pppCodeDiscardRequest   byte = 0x0B
)

const (
	pppIPCPOptionIPCompression byte = 0x002D
	pppIPCPOptionIPAddress     byte = 0x03
	pppIPCPOptionPrimaryDNS    byte = 0x81
	pppIPCPOptionSecondaryDNS  byte = 0x83
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
	opts := []pppOption{}
	b := payload.data
	for len(b) > 2 {
		opt := pppOption{
			type_:  b[0],
			length: uint8(b[1]),
		}
		if opt.length <= 2 {
			break
		}
		opt.value = b[2:opt.length]
		opts = append(opts, opt)
		b = b[opt.length:]
	}
	return opts
}

func (payload *pppPayload) setData(data []byte) {
	payload.data = data
	payload.length = uint16(len(data)) + 4
}

func newPPPPayload(code byte, identifier byte, data []byte) *pppPayload {
	return &pppPayload{
		code:       code,
		identifier: identifier,
		length:     uint16(len(data)) + 2,
		data:       data,
	}
}

func getLCPId() byte {
	pppLCPId++
	return byte(pppLCPId)
}

func resetLCPId() {
	pppLCPId = 0
}

type pppOption struct {
	type_  byte
	length uint8
	value  []byte
}

func encodePPPOptions(opts []pppOption) []byte {
	encBuf := new(bytes.Buffer)
	for _, o := range opts {
		if err := encBuf.WriteByte(o.type_); err != nil {
			return nil
		}
		if err := encBuf.WriteByte(o.length); err != nil {
			return nil
		}
		if _, err := encBuf.Write(o.value); err != nil {
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
			Protocol: request.header.Protocol,
		},
		payload: pppPayload{
			code:       request.payload.code + 1,
			identifier: request.payload.identifier,
			length:     0,
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
			Protocol: uint16(protocol),
		},
		payload: pppPayload{
			code:       code,
			identifier: reqId,
			length:     uint16(len(optsBytes)) + 4,
			data:       optsBytes,
		},
	}
}

func newLcpRequest(tid, sid ControlConnID, supportMRU, supportMagicNum bool) *pppDataMessage {
	resetLCPId()
	opts := []pppOption{}
	if supportMRU {
		mru := make([]byte, 2)
		binary.BigEndian.PutUint16(mru, pppLCPMRU)
		opts = append(opts, pppOption{
			type_:  pppLCPOptionMRU,
			length: 4,
			value:  mru,
		})
	}
	if supportMagicNum {
		magicNum := make([]byte, 4)
		binary.BigEndian.PutUint32(magicNum, pppLCPMagicNumber)
		opts = append(opts, pppOption{
			type_:  pppLCPOptionMagicNumber,
			length: 6,
			value:  magicNum,
		})
	}
	return newPPPMessage(tid, sid, pppProtocolLCP, pppCodeConfigureRequest, getLCPId(), opts)
}

func newPapRequest(tid, sid ControlConnID, peerId, password string) *pppDataMessage {
	resetLCPId()
	papRequest := &papRequest{
		peerIdLength:   uint8(len(peerId)),
		peerId:         peerId,
		passwordLength: uint8(len(password)),
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
			Protocol: uint16(pppProtocolPAP),
		},
		payload: pppPayload{
			code:       pppCodeConfigureRequest,
			identifier: getLCPId(),
			length:     uint16(len(papBytes)) + 4,
			data:       papBytes,
		},
	}
}

func newIpcpRequest(tid, sid ControlConnID, ipAddr []byte) *pppDataMessage {
	opts := []pppOption{}
	if ipAddr == nil {
		resetLCPId()
		opts = append(opts, pppOption{
			type_:  pppIPCPOptionIPAddress,
			length: 6,
			value:  []byte{0, 0, 0, 0},
		})
	} else {
		opts = append(opts, pppOption{
			type_:  pppIPCPOptionIPAddress,
			length: 6,
			value:  ipAddr,
		})
	}
	return newPPPMessage(tid, sid, pppProtocolIPCP, pppCodeConfigureRequest, getLCPId(), opts)
}

func newEchoReply(tid, sid ControlConnID, request *pppDataMessage) *pppDataMessage {
	magicNum := make([]byte, 4)
	binary.BigEndian.PutUint32(magicNum, pppLCPMagicNumber)
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			Protocol: request.header.Protocol,
		},
		payload: pppPayload{
			code:       request.payload.code + 1,
			identifier: request.payload.identifier,
			length:     8,
			data:       magicNum,
		},
	}
}

func newTerminateReply(tid, sid ControlConnID, request *pppDataMessage) *pppDataMessage {
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			Protocol: request.header.Protocol,
		},
		payload: pppPayload{
			code:       request.payload.code + 1,
			identifier: request.payload.identifier,
			length:     request.payload.length,
			data:       request.payload.data,
		},
	}
}

func newTerminateRequest(tid, sid ControlConnID) *pppDataMessage {
	resetLCPId()
	return &pppDataMessage{
		header: PPPDataHeader{
			FlagsVer: 0x0002,
			Tid:      uint16(tid),
			Sid:      uint16(sid),
			Address:  pppAddress,
			Control:  pppControl,
			Protocol: uint16(pppProtocolLCP),
		},
		payload: pppPayload{
			code:       pppCodeTerminateRequest,
			identifier: getLCPId(),
			length:     4,
			data:       nil,
		},
	}
}

type papRequest struct {
	peerIdLength   uint8
	peerId         string
	passwordLength uint8
	password       string
}

func (pap *papRequest) toBytes() []byte {
	encBuf := new(bytes.Buffer)
	if err := encBuf.WriteByte(pap.peerIdLength); err != nil {
		return nil
	}
	if _, err := encBuf.WriteString(pap.peerId); err != nil {
		return nil
	}
	if err := encBuf.WriteByte(pap.passwordLength); err != nil {
		return nil
	}
	if _, err := encBuf.WriteString(pap.password); err != nil {
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
	Protocol uint16
}

func NewPPPDataHeader(tid, sid ControlConnID, protocol uint16) *PPPDataHeader {
	return &PPPDataHeader{
		FlagsVer: 0x0002,
		Tid:      uint16(tid),
		Sid:      uint16(sid),
		Address:  pppAddress,
		Control:  pppControl,
		Protocol: protocol,
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
	msg, err := bytesToDataMsg(b)
	if err != nil {
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

	if err := binary.Write(buf, binary.BigEndian, m.payload.code); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, m.payload.identifier); err != nil {
		return nil, err
	}

	if err := binary.Write(buf, binary.BigEndian, m.payload.length); err != nil {
		return nil, err
	}

	if _, err := buf.Write(m.payload.data); err != nil {
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
	return pppProtocolType(m.header.Protocol)
}

func bytesToDataMsg(b []byte) (msg *pppDataMessage, err error) {
	buf := bytes.NewBuffer(b)
	msg = new(pppDataMessage)
	if err = binary.Read(buf, binary.BigEndian, &msg.header); err != nil {
		return nil, err
	}
	if msg.header.Protocol == uint16(pppProtocolIPV4) {
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
	p.data = b[4:]
	return nil
}
