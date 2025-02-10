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

	activeSession *vpnSessionDataPlane
}

type vpnTunnelDataPlane struct {
}

type vpnSessionDataPlane struct {
	vpnService VpnService
	vpnFd      int
	tunnelFd   int
	psid       l2tp.ControlConnID
	ptid       l2tp.ControlConnID
	isDown     bool
	logger     log.Logger
}

func (dpf *vpnDataPlane) NewTunnel(tcfg *l2tp.TunnelConfig, sal, sap unix.Sockaddr, fd int) (l2tp.TunnelDataPlane, error) {
	// control plane started
	dpf.tunnelFd = fd
	return &vpnTunnelDataPlane{}, nil
}

func (dpf *vpnDataPlane) NewSession(tid, ptid l2tp.ControlConnID, scfg *l2tp.SessionConfig) (l2tp.SessionDataPlane, error) {
	session := &vpnSessionDataPlane{
		vpnService: dpf.vpnService,
		vpnFd:      -1,
		tunnelFd:   dpf.tunnelFd,
		psid:       scfg.PeerSessionID,
		ptid:       ptid,
		isDown:     false,
		logger:     dpf.logger,
	}
	dpf.activeSession = session
	return session, nil
}

func (dpf *vpnDataPlane) Close() {
	if dpf.activeSession != nil {
		dpf.activeSession.Down()
	}
}

func (tdp *vpnTunnelDataPlane) Down() error {
	return nil
}

func (sdp *vpnSessionDataPlane) Start(ip []byte) error {
	if sdp.logger != nil {
		sdp.logger.Log("message", "starting vpn session", "ip", ip)
	}

	// TODO add session config, e.g. MTU, MRU, etc.
	sdp.vpnFd = sdp.vpnService.GetVpnFd(ip)
	if err := unix.SetNonblock(sdp.vpnFd, true); err != nil {
		if sdp.logger != nil {
			sdp.logger.Log("message", "setNonblock failed", "err", err)
		}
		return err
	}

	// session started
	// start reading from vpn fd, and writing to tunnel fd
	buffer := make([]byte, 4096)
	pppHeader := l2tp.NewPPPDataHeader(sdp.ptid, sdp.psid, uint16(0x0021)) // ipv4
	headerBytes := pppHeader.ToBytes()
	limitSize := 1500 - len(headerBytes)
	go func() {
		for !sdp.isDown {
			n, err := unix.Read(sdp.vpnFd, buffer)
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
		if sdp.logger != nil {
			sdp.logger.Log("message", "vpn session data plane exit")
		}
	}()
	return nil
}

func (sdp *vpnSessionDataPlane) GetStatistics() (*l2tp.SessionDataPlaneStatistics, error) {
	return nil, nil
}

func (sdp *vpnSessionDataPlane) GetInterfaceName() (string, error) {
	return "", nil
}

func (sdp *vpnSessionDataPlane) Down() error {
	if sdp.logger != nil {
		sdp.logger.Log("message", "vpn session data Donw")
	}
	sdp.isDown = true
	return nil
}

func (sdp *vpnSessionDataPlane) HandleDataPacket(data []byte) error {
	if sdp.vpnFd == -1 {
		return nil
	}
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
