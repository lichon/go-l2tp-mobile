package l2tp

import (
	"fmt"
	"sync"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type dynamicSession struct {
	*baseSession
	isClosed    bool
	established bool
	callSerial  uint32
	ifname      string
	result      string
	dt          *dynamicTunnel
	dp          SessionDataPlane
	wg          sync.WaitGroup
	pppRxChan   chan *pppDataMessage
	msgRxChan   chan controlMessage
	eventChan   chan string
	closeChan   chan interface{}
	killChan    chan interface{}
	fsm         fsm
}

func (ds *dynamicSession) Close() {
	ds.parent.unlinkSession(ds)
	close(ds.closeChan)
	ds.wg.Wait()
}

func (ds *dynamicSession) kill() {
	ds.parent.unlinkSession(ds)
	close(ds.killChan)
	ds.wg.Wait()
}

func (ds *dynamicSession) onTunnelUp() {
	ds.eventChan <- "tunnelopen"
}

func (ds *dynamicSession) handleCtlMsg(msg controlMessage) {
	ds.msgRxChan <- msg
}

func (ds *dynamicSession) runSession() {
	defer ds.wg.Done()

	level.Info(ds.logger).Log(
		"message", "new dynamic session",
		"session_id", ds.cfg.SessionID,
		"peer_session_id", ds.cfg.PeerSessionID,
		"pseudowire", ds.cfg.Pseudowire)

	for !ds.isClosed {
		select {
		case msg, _ := <-ds.pppRxChan:
			ds.handlePPPMsg(msg)
		case msg, ok := <-ds.msgRxChan:
			if !ok {
				ds.fsmActClose(nil)
				return
			}
			ds.handleMsg(msg)
		case ev, ok := <-ds.eventChan:
			if !ok {
				ds.fsmActClose(nil)
				return
			}
			ds.handleEvent(ev)
		case <-ds.killChan:
			ds.fsmActClose(nil)
			return
		case <-ds.closeChan:
			ds.handleEvent("close", avpCDNResultCodeAdminDisconnect)
			return
		}
	}
}

func (ds *dynamicSession) handleEvent(ev string, args ...interface{}) {
	if ev != "" {
		level.Debug(ds.logger).Log(
			"message", "fsm event",
			"event", ev)
		err := ds.fsm.handleEvent(ev, args...)
		if err != nil {
			level.Error(ds.logger).Log(
				"message", "failed to handle fsm event",
				"error", err)
			ds.fsmActClose(nil)
		}
	}
}

// panics if expected arguments are not passed
func fsmArgsToV2Msg(args []interface{}) (msg *v2ControlMessage) {
	if len(args) != 1 {
		panic(fmt.Sprintf("unexpected argument count (wanted 1, got %v)", len(args)))
	}
	msg, ok := args[0].(*v2ControlMessage)
	if !ok {
		panic(fmt.Sprintf("first argument %T not *v2ControlMessage", args[0]))
	}
	return
}

// cdn args are optional, we set defaults here
func fsmArgsToCdnResult(args []interface{}) *resultCode {
	rc := resultCode{
		result:  avpCDNResultCodeAdminDisconnect,
		errCode: avpErrorCodeNoError,
	}

	for i := 0; i < len(args); i++ {
		switch v := args[i].(type) {
		case avpResultCode:
			rc.result = v
		case avpErrorCode:
			rc.errCode = v
		case string:
			rc.errMsg = v
		}
	}

	return &rc
}

func cdnResultCodeToString(rc *resultCode) string {
	var resStr, errStr, errMsg string

	switch rc.result {
	case avpCDNResultCodeReserved:
		resStr = "reserved"
	case avpCDNResultCodeLostCarrier:
		resStr = "lost carrier"
	case avpCDNResultCodeGeneralError:
		resStr = "general error"
	case avpCDNResultCodeAdminDisconnect:
		resStr = "admin disconnect"
	case avpCDNResultCodeNoResources:
		resStr = "temporary lack of resources"
	case avpCDNResultCodeNotAvailable:
		resStr = "permanent lack of resources"
	case avpCDNResultCodeInvalidDestination:
		resStr = "invalid destination"
	case avpCDNResultCodeNoAnswer:
		resStr = "not carrier detected"
	case avpCDNResultCodeBusy:
		resStr = "busy signal detected"
	case avpCDNResultCodeNoDialTone:
		resStr = "no dial tone"
	case avpCDNResultCodeTimeout:
		resStr = "establish timeout"
	case avpCDNResultCodeBadTransport:
		resStr = "no appropriate framing detected"
	}

	switch rc.errCode {
	case avpErrorCodeNoError:
		errStr = "no general error"
	case avpErrorCodeNoControlConnection:
		errStr = "no control connection exists yet"
	case avpErrorCodeBadLength:
		errStr = "length is wrong"
	case avpErrorCodeBadValue:
		errStr = "field out of range or reserved field was non-zero"
	case avpErrorCodeNoResource:
		errStr = "insufficient resources to handle this operation now"
	case avpErrorCodeInvalidSessionID:
		errStr = "session ID invalid in this context"
	case avpErrorCodeVendorSpecificError:
		errStr = "generic vendor-specific error"
	case avpErrorCodeTryAnother:
		errStr = "try another LNS"
	case avpErrorCodeMBitShutdown:
		errStr = "shut down due to unknown AVP with the M bit set"
	}

	if rc.errMsg != "" {
		errMsg = rc.errMsg
	} else {
		errMsg = "unset"
	}

	return fmt.Sprintf("result %d (%s), error %d (%s), message '%s'",
		rc.result, resStr,
		rc.errCode, errStr,
		errMsg)
}

func (ds *dynamicSession) handleMsg(msg controlMessage) {

	switch msg.protocolVersion() {
	case ProtocolVersion2:
		msg, ok := msg.(*v2ControlMessage)
		if !ok {
			// This shouldn't occur, since the header protocol version
			// dictates the message type during parsing.  Bail out if
			// it does since it indicates some dire coding error.
			level.Error(ds.logger).Log(
				"message", "couldn't cast L2TPv2 message as v2ControlMessage")
			ds.fsmActClose(nil)
			return
		}
		ds.handleV2Msg(msg)
		return
	}

	level.Error(ds.logger).Log(
		"message", "unhandled protocol version",
		"version", msg.protocolVersion())
}

func (ds *dynamicSession) handlePPP(msg *pppDataMessage) {
	ds.pppRxChan <- msg
}

func (ds *dynamicSession) handlePPPMsg(msg *pppDataMessage) {
	if msg.Sid() != uint16(ds.cfg.SessionID) {
		level.Error(ds.logger).Log(
			"message", "received control message with the wrong SID",
			"expected", ds.cfg.SessionID,
			"got", msg.Sid())
		return
	}
	switch msg.Protocol() {
	case pppProtocolIPV4:
		ds.handleIPv4Msg(msg)
		break
	case pppProtocolLCP:
		ds.handleLcpMsg(msg)
		break
	case pppProtocolIPCP:
		ds.handleIpcpMsg(msg)
		break
	case pppProtocolPAP:
		ds.handlePapMsg(msg)
		break
	}
}

func (ds *dynamicSession) handleIPv4Msg(msg *pppDataMessage) {
	if ds.dp == nil {
		level.Debug(ds.logger).Log(
			"message", "got ipv4 packet, session dataplane is nil")
		return
	}
	err := ds.dp.HandleDataPacket(msg.payload.data)
	if err != nil {
		level.Debug(ds.logger).Log(
			"message", "failed to handle IPv4 packet",
			"error", err)
	}
}

func (ds *dynamicSession) handleLcpMsg(msg *pppDataMessage) {
	tid := ds.parent.getCfg().PeerTunnelID
	sid := ds.cfg.PeerSessionID
	supportedOpts := make([]pppOption, 0)
	rejectOpts := make([]pppOption, 0)

	level.Debug(ds.logger).Log(
		"message", "received lcp message",
		"code", msg.payload.code,
		"opts len", len(msg.payload.getOptions()),
	)

	if msg.payload.code == pppCodeConfigureRequest {
		supportMagicNumber := false
		supportMRU := false
		opts := msg.payload.getOptions()
		for _, opt := range opts {
			if opt.supportPap() {
				supportedOpts = append(supportedOpts, opt)
				continue
			}
			if opt.supportMagicNumber() {
				supportedOpts = append(supportedOpts, opt)
				supportMagicNumber = true
				continue
			}
			if opt.supportMRU() {
				supportedOpts = append(supportedOpts, opt)
				supportMRU = true
				continue
			}
			rejectOpts = append(rejectOpts, opt)
		}

		res := newPPPResponse(tid, sid, msg)
		if len(rejectOpts) > 0 {
			res.payload.code = pppCodeConfigureReject
			res.payload.setData(encodePPPOptions(rejectOpts))
			ds.dt.xport.sendMessage1(res, false)
		} else if len(supportedOpts) > 0 {
			res.payload.code = pppCodeConfigureAck
			res.payload.setData(encodePPPOptions(supportedOpts))
			ds.dt.xport.sendMessage1(res, false)

			// start lcp request
			// TODO support retry
			lcpReq := newLcpRequest(tid, sid, supportMRU, supportMagicNumber)
			ds.dt.xport.sendMessage1(lcpReq, false)
		}
	} else if msg.payload.code == pppCodeConfigureAck {
		req := newPapRequest(tid, sid, ds.cfg.PeerId, ds.cfg.Password)
		ds.dt.xport.sendMessage1(req, false)
	} else if msg.payload.code == pppCodeEchoRequest {
		res := newEchoReply(tid, sid, msg)
		ds.dt.xport.sendMessage1(res, false)
	} else if msg.payload.code == pppCodeTerminateRequest {
		res := newTerminateReply(tid, sid, msg)
		ds.dt.xport.sendMessage1(res, false)
		// session closed, notify
		ds.handleEvent("close", avpCDNResultCodeAdminDisconnect)
	}
}

func (ds *dynamicSession) handleIpcpMsg(msg *pppDataMessage) {
	tid := ds.parent.getCfg().PeerTunnelID
	sid := ds.cfg.PeerSessionID

	level.Debug(ds.logger).Log(
		"message", "received ipcp message",
		"code", msg.payload.code,
		"opts len", len(msg.payload.getOptions()),
	)

	if msg.payload.code == pppCodeConfigureRequest {
		opts := msg.payload.getOptions()
		// accept all options
		res := newPPPResponse(tid, sid, msg)
		res.payload.code = pppCodeConfigureAck
		res.payload.setData(encodePPPOptions(opts))
		ds.dt.xport.sendMessage1(res, false)
	} else if msg.payload.code == pppCodeConfigureNak {
		opts := msg.payload.getOptions()
		ip := []byte{0, 0, 0, 0}
		foundIp := false
		for _, opt := range opts {
			if opt.type_ == pppIPCPOptionIPAddress {
				ip = opt.value
				foundIp = true
				break
			}
		}
		req := newIpcpRequest(tid, sid, ip)
		ds.dt.xport.sendMessage1(req, false)
		if foundIp {
			ds.dp.Start(ip)
		}
	}
}

func (ds *dynamicSession) handlePapMsg(msg *pppDataMessage) {
	tid := ds.parent.getCfg().PeerTunnelID
	sid := ds.cfg.PeerSessionID

	level.Debug(ds.logger).Log(
		"message", "received pap message",
		"code", msg.payload.code,
	)
	if msg.payload.code == pppCodeConfigureAck {
		// auth success
		req := newIpcpRequest(tid, sid, nil)
		ds.dt.xport.sendMessage1(req, false)
	} else if msg.payload.code == pppCodeConfigureAck {
		// close session
		ds.handleEvent("close", avpStopCCNResultCodeChannelNotAuthorized)
	}
}

func (ds *dynamicSession) closeLcp() {
	tid := ds.parent.getCfg().PeerTunnelID
	sid := ds.cfg.PeerSessionID
	req := newTerminateRequest(tid, sid)
	ds.dt.xport.sendMessage1(req, false)
}

func (ds *dynamicSession) handleV2Msg(msg *v2ControlMessage) {

	// It's possible to have a message mis-delivered on our control
	// socket.  Ignore these messages: ideally we'd redirect them
	// but dropping them is a good compromise for now.
	if msg.Sid() != uint16(ds.cfg.SessionID) {
		level.Error(ds.logger).Log(
			"message", "received control message with the wrong SID",
			"expected", ds.cfg.SessionID,
			"got", msg.Sid())
		return
	}

	// Validate the message.  If validation fails drive shutdown via.
	// the FSM to allow the error to be communicated to the peer.
	err := msg.validate()
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "bad control message",
			"message_type", msg.getType(),
			"error", err)
		ds.handleEvent("close",
			avpCDNResultCodeGeneralError,
			avpErrorCodeBadValue,
			fmt.Sprintf("bad %v message: %v", msg.getType(), err))
	}

	// Map the message to the appropriate event type.  If we haven't got
	// an event appropriate to the incoming message close the tunnel.
	eventMap := []struct {
		m avpMsgType
		e string
	}{
		{avpMsgTypeIcrq, "icrq"},
		{avpMsgTypeIcrp, "icrp"},
		{avpMsgTypeIccn, "iccn"},
		{avpMsgTypeCdn, "cdn"},
	}

	for _, em := range eventMap {
		if msg.getType() == em.m {
			ds.handleEvent(em.e, msg)
			return
		}
	}

	level.Error(ds.logger).Log(
		"message", "unhandled v2 control message",
		"message_type", msg.getType())

	ds.handleEvent("close",
		avpCDNResultCodeGeneralError,
		avpErrorCodeBadValue,
		fmt.Sprintf("unhandled v2 control message %v", msg.getType()))
}

func (ds *dynamicSession) sendMessage(msg controlMessage) {
	err := ds.dt.sendMessage(msg)
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "failed to send control message",
			"message_type", msg.getType(),
			"error", err)
		ds.fsmActClose(nil)
	}
}

func (ds *dynamicSession) fsmActSendIcrq(args []interface{}) {
	err := ds.sendIcrq()
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "failed to send ICRQ message",
			"error", err)
		ds.fsmActClose(nil)
	}
}

func (ds *dynamicSession) sendIcrq() (err error) {
	msg, err := newV2Icrq(ds.callSerial, ds.parent.getCfg().PeerTunnelID, ds.cfg)
	if err != nil {
		return err
	}
	ds.sendMessage(msg)
	return
}

func (ds *dynamicSession) fsmActOnIcrp(args []interface{}) {
	msg := fsmArgsToV2Msg(args)

	psid, err := findUint16Avp(msg.getAvps(), vendorIDIetf, avpTypeSessionID)
	if err != nil {
		// Shouldn't occur since session ID is mandatory
		level.Error(ds.logger).Log(
			"message", "failed to parse peer session ID from ICRP",
			"error", err)
		ds.handleEvent("close",
			avpCDNResultCodeGeneralError,
			avpErrorCodeBadValue,
			"no Assigned Session ID AVP in ICRP message")
		return
	}

	ds.cfg.PeerSessionID = ControlConnID(psid)

	err = ds.sendIccn()
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "failed to send ICCN",
			"error", err)
		// TODO: CDN args
		ds.fsmActClose(nil)
		return
	}

	level.Info(ds.logger).Log("message", "control plane established")

	// establish the data plane
	ds.dp, err = ds.parent.getDP().NewSession(
		ds.parent.getCfg().TunnelID,
		ds.parent.getCfg().PeerTunnelID,
		ds.cfg)
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "failed to establish data plane",
			"error", err)
		// TODO: CDN args
		ds.fsmActClose(nil)
		return
	}

	ds.ifname, err = ds.dp.GetInterfaceName()
	if err != nil {
		level.Error(ds.logger).Log(
			"message", "failed to retrieve session interface name",
			"error", err)
		// TODO: CDN args
		ds.fsmActClose(nil)
	}

	level.Info(ds.logger).Log("message", "data plane established")

	ds.established = true
	ds.parent.handleUserEvent(&SessionUpEvent{
		TunnelName:    ds.parent.getName(),
		Tunnel:        ds.parent,
		TunnelConfig:  ds.parent.getCfg(),
		SessionName:   ds.getName(),
		Session:       ds,
		SessionConfig: ds.cfg,
		InterfaceName: ds.ifname,
	})
}

func (ds *dynamicSession) sendIccn() (err error) {
	msg, err := newV2Iccn(ds.parent.getCfg().PeerTunnelID, ds.cfg)
	if err != nil {
		return err
	}
	ds.sendMessage(msg)
	return
}

func (ds *dynamicSession) fsmActSendCdn(args []interface{}) {
	rc := fsmArgsToCdnResult(args)
	if ds.result == "" {
		ds.result = cdnResultCodeToString(rc)
	}
	_ = ds.sendCdn(rc)
	ds.fsmActClose(args)
}

func (ds *dynamicSession) sendCdn(rc *resultCode) (err error) {
	msg, err := newV2Cdn(ds.parent.getCfg().PeerTunnelID, rc, ds.cfg)
	if err != nil {
		return err
	}
	ds.sendMessage(msg)
	return
}

func (ds *dynamicSession) fsmActOnCdn(args []interface{}) {
	msg := fsmArgsToV2Msg(args)

	rc, err := findResultCodeAvp(msg.getAvps(), vendorIDIetf, avpTypeResultCode)
	if err == nil && ds.result == "" {
		ds.result = cdnResultCodeToString(rc)
	}

	ds.fsmActClose(args)
}

func (ds *dynamicSession) fsmActClose(args []interface{}) {
	if ds.dp != nil {
		err := ds.dp.Down()
		if err != nil {
			level.Error(ds.logger).Log("message", "dataplane down failed", "error", err)
		}
	}

	if ds.established {
		ds.closeLcp()
		ds.established = false
		ds.parent.handleUserEvent(&SessionDownEvent{
			TunnelName:    ds.parent.getName(),
			Tunnel:        ds.parent,
			TunnelConfig:  ds.parent.getCfg(),
			SessionName:   ds.getName(),
			Session:       ds,
			SessionConfig: ds.cfg,
			InterfaceName: ds.ifname,
			Result:        ds.result,
		})
	}

	ds.parent.unlinkSession(ds)
	level.Info(ds.logger).Log("message", "close")
	ds.isClosed = true
}

// Create a new client/LAC mode session instance
func newDynamicSession(serial uint32, name string, parent *dynamicTunnel, cfg *SessionConfig) (ds *dynamicSession, err error) {

	ds = &dynamicSession{
		baseSession: newBaseSession(
			log.With(parent.getLogger(), "session_name", name),
			name,
			parent,
			cfg),
		callSerial: serial,
		dt:         parent,
		pppRxChan:  make(chan *pppDataMessage),
		msgRxChan:  make(chan controlMessage),
		eventChan:  make(chan string),
		closeChan:  make(chan interface{}),
		killChan:   make(chan interface{}),
	}

	// Ref: RFC2661 section 7.4.1
	ds.fsm = fsm{
		current: "waittunnel",
		table: []eventDesc{
			{from: "waittunnel", events: []string{"tunnelopen"}, cb: ds.fsmActSendIcrq, to: "waitreply"},
			{from: "waittunnel", events: []string{"close"}, cb: ds.fsmActClose, to: "dead"},

			{from: "waitreply", events: []string{"icrp"}, cb: ds.fsmActOnIcrp, to: "established"},
			{from: "waitreply", events: []string{"iccn"}, cb: ds.fsmActClose, to: "dead"},
			{from: "waitreply", events: []string{"cdn"}, cb: ds.fsmActOnCdn, to: "dead"},
			{from: "waitreply", events: []string{"icrq", "close"}, cb: ds.fsmActSendCdn, to: "dead"},

			{from: "established", events: []string{"cdn"}, cb: ds.fsmActOnCdn, to: "dead"},
			{
				from: "established",
				events: []string{
					"icrq",
					"icrp",
					"iccn",
					"close",
				},
				cb: ds.fsmActSendCdn,
				to: "dead",
			},
		},
	}

	ds.wg.Add(1)
	go ds.runSession()

	return
}
