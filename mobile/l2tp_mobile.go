package l2tpMobile

import (
	"errors"
	"fmt"

	"go-l2tp-mobile/config"
	"go-l2tp-mobile/l2tp"

	"github.com/go-kit/kit/log"
	_ "golang.org/x/mobile/bind"
)

type application struct {
	cfg        *config.Config
	l2tpCtx    *l2tp.Context
	vpnService VpnService
}

type LogWriter interface {
	Write(log []byte) (n int, err error)
}

// VpnService should be implemented in Java/Kotlin.
type VpnService interface {
	// Protect is just a proxy to the VpnService.protect() method.
	// See also: https://developer.android.com/reference/android/net/VpnService.html#protect(int)
	Protect(fd int) bool
}

// PacketFlow should be implemented in Java/Kotlin.
type PacketFlow interface {
	// WritePacket should writes packets to the TUN fd.
	Write(packet []byte) (int, error)
}

var l2tpApp *application

func newApplication(cfg *config.Config, logWriter LogWriter, vpnService VpnService) (app *application, err error) {
	app = &application{
		cfg:        cfg,
		vpnService: vpnService,
	}

	logger := log.NewLogfmtLogger(logWriter)
	app.l2tpCtx, err = l2tp.NewUserContext(nil, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create L2TP context: %v", err)
	}

	return app, nil
}

func (app *application) start() (err error) {
	// Listen for L2TP events
	app.l2tpCtx.RegisterEventHandler(app)

	// Instantiate tunnels and sessions from the config file
	for _, tcfg := range app.cfg.Tunnels {

		// Only support l2tpv2/ppp
		if tcfg.Config.Version != l2tp.ProtocolVersion2 {
			return errors.New("only l2tpv2 is supported")
		}

		tunl, err := app.l2tpCtx.NewDynamicTunnel(tcfg.Name, tcfg.Config)
		if err != nil {
			return err
		}

		// Protect the tunnel's file descriptor
		if !app.vpnService.Protect(tunl.ControlPlaneFd()) {
			return errors.New("failed to protect tunnel file descriptor")
		}

		for _, scfg := range tcfg.Sessions {
			_, err := tunl.NewSession(scfg.Name, scfg.Config)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (app *application) stop() {
	go func() {
		app.l2tpCtx.Close()
	}()
}

func (app *application) HandleEvent(event interface{}) {
	switch event.(type) {
	case *l2tp.TunnelUpEvent:
		// log

	case *l2tp.TunnelDownEvent:
		// log

	case *l2tp.SessionUpEvent:
		// log

	case *l2tp.SessionDownEvent:
		// log
	}
}

// StartL2tp
// connection handler for l2tp
func StartL2tp(
	packetFlow PacketFlow,
	vpnService VpnService,
	logWriter LogWriter,
	configBytes []byte) error {
	if packetFlow != nil {
		l2tpConfig, err := config.LoadString(string(configBytes))
		if err != nil {
			return errors.New(fmt.Sprintf("failed to parse config: %v", err))
		}
		l2tpApp, err = newApplication(l2tpConfig, logWriter, vpnService)
		if err != nil {
			return errors.New(fmt.Sprintf("failed to create L2TP context: %v", err))
		}
		l2tpApp.start()
		return nil
	}
	return errors.New("packetFlow is null")
}

// StopL2tp
func StopL2tp() {
	if l2tpApp != nil {
		l2tpApp.stop()
	}
}
