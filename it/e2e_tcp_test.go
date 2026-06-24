package it

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcuadros/go-defaults"
	"github.com/semgrep/semgrep-network-broker/cmd"
	"github.com/semgrep/semgrep-network-broker/pkg"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// startTcpToUdpShim stands in for the gateway's TCP WireGuard listener. It
// accepts framed TCP connections from the broker, decapsulates them into UDP
// datagrams aimed at the real (UDP) WireGuard gateway, and re-frames the UDP
// replies back over the same TCP connection. This mirrors the gateway-side
// encapsulation in semgrep-private-link PR #86 and proves the broker's TCP
// transport interoperates with a genuine WireGuard device.
func startTcpToUdpShim(t *testing.T, udpTarget string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start tcp shim: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			tcpConn, err := ln.Accept()
			if err != nil {
				return
			}
			go bridgeTcpToUdp(tcpConn, udpTarget)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func bridgeTcpToUdp(tcpConn net.Conn, udpTarget string) {
	defer tcpConn.Close()

	raddr, err := net.ResolveUDPAddr("udp", udpTarget)
	if err != nil {
		return
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer udpConn.Close()

	// UDP replies from the gateway -> framed TCP back to the broker
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				tcpConn.Close()
				return
			}
			var header [2]byte
			binary.BigEndian.PutUint16(header[:], uint16(n))
			if _, err := tcpConn.Write(append(header[:], buf[:n]...)); err != nil {
				return
			}
		}
	}()

	// Framed TCP from the broker -> UDP datagrams to the gateway
	for {
		var header [2]byte
		if _, err := io.ReadFull(tcpConn, header[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(header[:])
		if length == 0 {
			continue
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(tcpConn, payload); err != nil {
			return
		}
		if _, err := udpConn.Write(payload); err != nil {
			return
		}
	}
}

func TestWireguardInboundProxyOverTcp(t *testing.T) {
	gatewayWireguardPort := mustGetFreePort()
	gatewayWireguardAddress := mustGetRandomPrivateAddress()
	gatewayPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	gatewayPublicKey := gatewayPrivateKey.PublicKey()

	clientPrivateKey, _ := wgtypes.GeneratePrivateKey()
	clientPublicKey := clientPrivateKey.PublicKey()
	clientWireguardAddress := mustGetRandomPrivateAddress()

	// setup "remote" wireguard peer (the gateway), speaking plain UDP
	remoteWireguardConfig := &pkg.WireguardBase{
		LocalAddress: gatewayWireguardAddress.String(),
		PrivateKey:   gatewayPrivateKey[:],
		Peers: []pkg.WireguardPeer{
			{
				PublicKey:                  clientPublicKey[:],
				AllowedIps:                 fmt.Sprintf("%v/128", clientWireguardAddress),
				DisablePersistentKeepalive: true,
			},
		},
		ListenPort: gatewayWireguardPort,
	}
	defaults.SetDefaults(remoteWireguardConfig)

	remoteWireguard, remoteWireguardTeardown, err := remoteWireguardConfig.Start()
	if err != nil {
		t.Errorf("failed to setup remote wireguard: %v", err)
	}
	defer remoteWireguardTeardown()
	log.Info("Remote wireguard peer is up")

	// stand up the TCP->UDP shim in front of the gateway's UDP listener
	shimTcpPort := startTcpToUdpShim(t, fmt.Sprintf("127.0.0.1:%d", gatewayWireguardPort))
	log.WithField("tcp_port", shimTcpPort).Info("TCP shim is up")

	// set up internal service (the thing that the broker proxies to)
	internalServer := gin.Default()
	internalServer.UseRawPath = true
	internalServer.UnescapePathValues = false
	internalServer.Any("/allowed-get", func(ctx *gin.Context) {
		ctx.String(200, "Hello")
	})

	internalListener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Errorf("Failed to start internal listener: %v", err)
	}
	defer internalListener.Close()
	go internalServer.RunListener(internalListener)
	log.Info("Internal server is up")

	internalServerBaseUrl := fmt.Sprintf("http://%v", internalListener.Addr().String())

	// start network broker with TCP transport enabled. The peer endpoint host
	// (127.0.0.1) is reused; TcpTransportPort points at the shim.
	brokerConfig := &pkg.Config{
		Inbound: pkg.InboundProxyConfig{
			Wireguard: pkg.WireguardBase{
				LocalAddress: clientWireguardAddress.String(),
				PrivateKey:   clientPrivateKey[:],
				Peers: []pkg.WireguardPeer{
					{
						PublicKey:  gatewayPublicKey[:],
						AllowedIps: fmt.Sprintf("%v/128", gatewayWireguardAddress),
						Endpoint:   fmt.Sprintf("127.0.0.1:%v", gatewayWireguardPort),
					},
				},
				TcpTransportPort: shimTcpPort,
			},
			Allowlist: []pkg.AllowlistItem{
				{
					URL:     internalServerBaseUrl + "/allowed-get",
					Methods: pkg.ParseHttpMethods([]string{"GET"}),
				},
			},
			Heartbeat: pkg.HeartbeatConfig{
				URL: fmt.Sprintf("http://[%v]/ping", gatewayWireguardAddress),
			},
		},
	}
	defaults.SetDefaults(brokerConfig)

	teardown, err := cmd.StartNetworkBroker(brokerConfig)
	if err != nil {
		log.Error(err)
	}
	defer teardown()
	log.Info("Network broker is up (TCP transport)")

	// set up "remote" HTTP client that dials through the gateway wireguard
	remoteHttpClient := testClient{
		Client: &http.Client{
			Transport: &http.Transport{
				DialContext: remoteWireguard.DialContext,
			},
			Timeout: 5 * time.Second,
		},
		PeerAddress: clientWireguardAddress,
	}

	// The tunnel comes up only once the broker's persistent keepalive triggers a
	// handshake over TCP, so retry until the proxied request succeeds.
	assertEventually(t, 15*time.Second, func() bool {
		url := fmt.Sprintf("http://[%v]/proxy/%v/allowed-get", clientWireguardAddress, internalServerBaseUrl)
		statusCode, _, err := remoteHttpClient.Request(mustGetRequest(t, "GET", url))
		return err == nil && statusCode == 200
	})
}

func mustGetRequest(t *testing.T, method string, rawUrl string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawUrl, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	return req
}

func assertEventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
