package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go-l2tp-mobile/l2tp"
)

func TestGetTunnels(t *testing.T) {
	cases := []struct {
		in   string
		want []NamedTunnel
	}{
		{
			in: `[tunnel.t1]
				 encap = "ip"
				 version = "l2tpv3"
				 peer = "82.9.90.101:1701"
				 tid = 412
				 ptid = 8192
				 framing_caps = ["sync"]
				 host_name = "blackhole.local"

				 [tunnel.t2]
				 encap = "udp"
				 version = "l2tpv2"
				 peer = "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]:6543"
				 hello_timeout = 250
				 window_size = 10
				 retry_timeout = 250
				 max_retries = 2
				 framing_caps = ["sync","async"]
				 `,
			want: []NamedTunnel{
				{
					Name: "t1",
					Config: &l2tp.TunnelConfig{
						Encap:        l2tp.EncapTypeIP,
						Version:      l2tp.ProtocolVersion3,
						Peer:         "82.9.90.101:1701",
						TunnelID:     412,
						PeerTunnelID: 8192,
						FramingCaps:  l2tp.FramingCapSync,
						HostName:     "blackhole.local",
					},
				},
				{
					Name: "t2",
					Config: &l2tp.TunnelConfig{
						Encap:        l2tp.EncapTypeUDP,
						Version:      l2tp.ProtocolVersion2,
						Peer:         "[2001:0000:1234:0000:0000:C1C0:ABCD:0876]:6543",
						HelloTimeout: 250 * time.Millisecond,
						WindowSize:   10,
						RetryTimeout: 250 * time.Millisecond,
						MaxRetries:   2,
						FramingCaps:  l2tp.FramingCapSync | l2tp.FramingCapAsync,
					},
				},
			},
		},
		{
			in: `[tunnel.t1]
				 encap = "ip"
				 version = "l2tpv3"
				 peer = "127.0.0.1:5001"

				 [tunnel.t1.session.s1]
				 pseudowire = "eth"
				 cookie = [ 0x34, 0x04, 0xa9, 0xbe ]
				 peer_cookie = [ 0x80, 0x12, 0xff, 0x5b ]
				 seqnum = true
				 reorder_timeout = 1500
				 l2spec_type = "none"

				 [tunnel.t1.session.s2]
				 pseudowire = "ppp"
				 sid = 90210
				 psid = 1237812
				 interface_name = "becky"
				 l2spec_type = "default"

				 [tunnel.t1.session.s3]
				 pseudowire = "pppac"
				 pppoe_session_id = 5612
				 pppoe_peer_mac = [ 0xca, 0x6b, 0x7e, 0x93, 0xc4, 0xc3 ]
				`,
			want: []NamedTunnel{
				{
					Name: "t1",
					Config: &l2tp.TunnelConfig{
						Encap:       l2tp.EncapTypeIP,
						Version:     l2tp.ProtocolVersion3,
						Peer:        "127.0.0.1:5001",
						FramingCaps: l2tp.FramingCapSync | l2tp.FramingCapAsync,
					},
					Sessions: []NamedSession{
						{
							Name: "s1",
							Config: &l2tp.SessionConfig{
								Pseudowire:     l2tp.PseudowireTypeEth,
								Cookie:         []byte{0x34, 0x04, 0xa9, 0xbe},
								PeerCookie:     []byte{0x80, 0x12, 0xff, 0x5b},
								SeqNum:         true,
								ReorderTimeout: time.Millisecond * 1500,
								L2SpecType:     l2tp.L2SpecTypeNone,
							},
						},
						{
							Name: "s2",
							Config: &l2tp.SessionConfig{
								Pseudowire:    l2tp.PseudowireTypePPP,
								SessionID:     90210,
								PeerSessionID: 1237812,
								InterfaceName: "becky",
								L2SpecType:    l2tp.L2SpecTypeDefault,
							},
						},
						{
							Name: "s3",
							Config: &l2tp.SessionConfig{
								Pseudowire:     l2tp.PseudowireTypePPPAC,
								PPPoESessionId: 5612,
								PPPoEPeerMac:   [6]byte{0xca, 0x6b, 0x7e, 0x93, 0xc4, 0xc3},
							},
						},
					},
				},
			},
		},
	}
	for _, c := range cases {
		cfg, err := LoadString(c.in)
		if err != nil {
			t.Fatalf("LoadString(%v): %v", c.in, err)
		}
		for _, want_t := range c.want {
			got_t, err := cfg.findTunnelByName(want_t.Name)
			if err != nil {
				t.Fatalf("missing tunnel: %v", err)
			}
			for _, want_s := range want_t.Sessions {
				got_s, err := got_t.findSessionByName(want_s.Name)
				if err != nil {
					t.Fatalf("missing session: %v", err)
				}
				if !reflect.DeepEqual(got_s, &want_s) {
					t.Fatalf("got %v, want %v", got_s, want_s)
				}
			}
		}
	}
}

func (c *Config) findTunnelByName(name string) (*NamedTunnel, error) {
	for _, t := range c.Tunnels {
		if t.Name == name {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("no tunnel of name %s", name)
}

func (t *NamedTunnel) findSessionByName(name string) (*NamedSession, error) {
	for _, s := range t.Sessions {
		if s.Name == name {
			return &s, nil
		}
	}
	return nil, fmt.Errorf("no session of name %s", name)
}

func TestBadConfig(t *testing.T) {
	cases := []struct {
		name string
		in   string
		estr string
	}{
		{
			name: "Bad type (int not string)",
			in: `[tunnel.t1]
				 encap = 42`,
			estr: "could not be parsed as a string",
		},
		{
			name: "Bad type (float not string)",
			in: `[tunnel.t1]
				 encap = 42.21`,
			estr: "could not be parsed as a string",
		},
		{
			name: "Bad type (array not string)",
			in: `[tunnel.t1]
				 version = [0x12, 0x34]`,
			estr: "could not be parsed as a string",
		},
		{
			name: "Bad type (bool not string)",
			in: `[tunnel.t1]
				 encap = false`,
			estr: "could not be parsed as a string",
		},
		{
			name: "Bad value (unrecognised encap)",
			in: `[tunnel.t1]
				 encap = "sausage"`,
			estr: "expect 'udp' or 'ip'",
		},
		{
			name: "Bad value (unrecognised version)",
			in: `[tunnel.t1]
				 version = "2001"`,
			estr: "expect 'l2tpv2' or 'l2tpv3'",
		},
		{
			name: "Bad value (unrecognised pseudowire)",
			in: `[tunnel.t1]
				 [tunnel.t1.session.s1]
				 pseudowire = "monkey"`,
			estr: "expect 'ppp', 'eth', or 'pppac'",
		},
		{
			name: "Bad value (unrecognised L2SpecType)",
			in: `[tunnel.t1]
				 [tunnel.t1.session.s1]
				 l2spec_type = "whizzoo"`,
			estr: "expect 'none' or 'default'",
		},
		{
			name: "Bad value (unrecognised FramingCap)",
			in: `[tunnel.t1]
				 framing_caps = [ "bizzle" ]`,
			estr: "expect 'sync' or 'async'",
		},
		{
			name: "Bad value (range exceeded)",
			in: `[tunnel.t1]
				 tid = 4294967297`,
			estr: "out of range",
		},
		{
			name: "Bad value (range exceeded)",
			in: `[tunnel.t1]
				 [tunnel.t1.session.s1]
				 cookie = [ 0x1e, 0xf0, 0x1fe, 0x24 ]`,
			estr: "out of range",
		},
		{
			name: "Malformed (no tunnel name)",
			in:   `[tunnel]`,
			estr: "tunnel instances must be named",
		},
		{
			name: "Malformed (no tunnel name 2)",
			in:   `tunnel = "t1"`,
			estr: "tunnel instances must be named",
		},
		{
			name: "Malformed (no session name)",
			in: `[tunnel.t1]
				 version = "l2tpv3"
				 [tunnel.t1.session]
				 pseudowire = "udp"`,
			estr: "session instances must be named",
		},
		{
			name: "Malformed (no session name)",
			in: `[tunnel.t1]
				 version = "l2tpv3"
				 session = 42`,
			estr: "session instances must be named",
		},
		{
			name: "Malformed (bad tunnel parameter)",
			in: `[tunnel.t1]
				 monkey = "banana"`,
			estr: "unrecognised parameter",
		},
		{
			name: "Malformed (bad session parameter)",
			in: `[tunnel.t1]
				 [tunnel.t1.session.s1]
				 whizz = 42`,
			estr: "unrecognised parameter",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadString(tt.in)
			if err == nil {
				t.Fatalf("LoadString(%v) succeeded when we expected an error", tt.in)
			}
			if !strings.Contains(err.Error(), tt.estr) {
				t.Fatalf("LoadString(%v): error %q doesn't contain expected substring %q", tt.in, err, tt.estr)
			}
		})
	}
}
