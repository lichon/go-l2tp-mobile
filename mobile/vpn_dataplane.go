package l2tpMobile

import (
	"go-l2tp-mobile/l2tp"

	"golang.org/x/sys/unix"
)

var _ l2tp.DataPlane = (*vpnDataPlane)(nil)
var _ l2tp.TunnelDataPlane = (*vpnTunnelDataPlane)(nil)
var _ l2tp.SessionDataPlane = (*vpnSessionDataPlane)(nil)

type vpnDataPlane struct {
	vpnService VpnService
	tunnelFd   int
}

type vpnTunnelDataPlane struct {
	f *vpnDataPlane
}

type vpnSessionDataPlane struct {
	f     *vpnDataPlane
	vpnFd int
}

func (dpf *vpnDataPlane) NewTunnel(tcfg *l2tp.TunnelConfig, sal, sap unix.Sockaddr, fd int) (l2tp.TunnelDataPlane, error) {
	// control plane started
	dpf.tunnelFd = fd
	return &vpnTunnelDataPlane{f: dpf}, nil
}

func (dpf *vpnDataPlane) NewSession(tid, ptid l2tp.ControlConnID, scfg *l2tp.SessionConfig) (l2tp.SessionDataPlane, error) {
	// session started
	// start reading from vpn fd, and writing to tunnel fd
	// TODO get session config, e.g. MTU, MRU, etc.
	fd := dpf.vpnService.GetVpnFd()
	return &vpnSessionDataPlane{f: dpf, vpnFd: fd}, nil
}

func (dpf *vpnDataPlane) Close() {
}

func (tdp *vpnTunnelDataPlane) Down() error {
	return nil
}

func (sdp *vpnSessionDataPlane) GetStatistics() (*l2tp.SessionDataPlaneStatistics, error) {
	return nil, nil
}

func (sdp *vpnSessionDataPlane) GetInterfaceName() (string, error) {
	return "", nil
}

func (sdp *vpnSessionDataPlane) Down() error {
	return nil
}

func (sdp *vpnSessionDataPlane) HandleDataPacket(data []byte) error {
	return unix.Write(sdp.vpnFd, data)
}

func newVpnDataPlane(vpnService VpnService) (l2tp.DataPlane, error) {
	return &vpnDataPlane{
		vpnService: vpnService,
		tunnelFd:   -1,
	}, nil
}
