package l2tpMobile

import (
	"go-l2tp-mobile/l2tp"

	"github.com/go-kit/log"
	"golang.org/x/sys/unix"
)

var _ l2tp.DataPlane = (*vpnDataPlane)(nil)
var _ l2tp.TunnelDataPlane = (*vpnTunnelDataPlane)(nil)
var _ l2tp.SessionDataPlane = (*vpnSessionDataPlane)(nil)

type vpnDataPlane struct {
	vpnService VpnService
	logger     log.Logger
	tunnelFd   int
}

type vpnTunnelDataPlane struct {
}

type vpnSessionDataPlane struct {
	vpnFd    int
	tunnelFd int
	tid      l2tp.ControlConnID
	ptid     l2tp.ControlConnID
	isDown   bool
	logger   log.Logger
}

func (dpf *vpnDataPlane) NewTunnel(tcfg *l2tp.TunnelConfig, sal, sap unix.Sockaddr, fd int) (l2tp.TunnelDataPlane, error) {
	// control plane started
	dpf.tunnelFd = fd
	return &vpnTunnelDataPlane{}, nil
}

func (dpf *vpnDataPlane) NewSession(tid, ptid l2tp.ControlConnID, scfg *l2tp.SessionConfig) (l2tp.SessionDataPlane, error) {
	// session started
	// start reading from vpn fd, and writing to tunnel fd
	// TODO get session config, e.g. MTU, MRU, etc.
	fd := dpf.vpnService.GetVpnFd()
	session := &vpnSessionDataPlane{vpnFd: fd, tunnelFd: dpf.tunnelFd, tid: tid, ptid: ptid, isDown: false}
	session.logger = dpf.logger
	go session.start()
	return session, nil
}

func (dpf *vpnDataPlane) Close() {
}

func (tdp *vpnTunnelDataPlane) Down() error {
	return nil
}

func (sdp *vpnSessionDataPlane) start() {
	buffer := make([]byte, 4096)
	pppHeader := l2tp.NewPPPDataHeader(sdp.tid, sdp.ptid, uint16(0x0021)) // ipv4
	headerBytes := pppHeader.ToBytes()
	limitSize := 1500 - len(headerBytes)
	for !sdp.isDown {
		n, err := unix.Read(sdp.vpnFd, buffer)
		if sdp.logger != nil {
			sdp.logger.Log(
				"message", "read from vpn fd",
				"len", n,
				"err", err)
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || n > limitSize {
			// skip over size limit packets
			continue
		}
		if err != nil {
			break
		}
		if err == nil && n > 0 {
			unix.Write(sdp.tunnelFd, append(headerBytes, buffer[:n]...))
		}
	}
}

func (sdp *vpnSessionDataPlane) GetStatistics() (*l2tp.SessionDataPlaneStatistics, error) {
	return nil, nil
}

func (sdp *vpnSessionDataPlane) GetInterfaceName() (string, error) {
	return "", nil
}

func (sdp *vpnSessionDataPlane) Down() error {
	sdp.isDown = true
	return nil
}

func (sdp *vpnSessionDataPlane) HandleDataPacket(data []byte) error {
	_, err := unix.Write(sdp.vpnFd, data)
	if sdp.logger != nil {
		sdp.logger.Log(
			"message", "write to vpn fd",
			"len", len(data),
			"err", err)
	}
	return err
}

func newVpnDataPlane(vpnService VpnService, logger log.Logger) (l2tp.DataPlane, error) {
	return &vpnDataPlane{
		vpnService: vpnService,
		logger:     logger,
		tunnelFd:   -1,
	}, nil
}
