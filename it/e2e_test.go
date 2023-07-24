package it

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mcuadros/go-defaults"
	"github.com/returntocorp/semgrep-network-broker/cmd"
	"github.com/returntocorp/semgrep-network-broker/pkg"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustGetRandomPrivateAddress() netip.Addr {
	addrBytes := netip.MustParseAddr("fdf0:59dc:33cf:9be8::0").AsSlice()
	rand.Read(addrBytes[8:])
	addr, ok := netip.AddrFromSlice(addrBytes)
	if !ok {
		panic("Failed to make random address")
	}
	return addr
}

func mustGetFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type testClient struct {
	PeerAddress netip.Addr
	Client      *http.Client
}

func (tc *testClient) Request(method string, rawUrl string) (int, string, error) {
	url, err := url.Parse(rawUrl)
	if err != nil {
		return 0, "", err
	}

	req := &http.Request{
		Method: method,
		URL:    url,
	}
	resp, err := tc.Client.Do(req)
	if err != nil {
		return 0, "", err
	}

	defer resp.Body.Close()

	content := new(strings.Builder)
	io.Copy(content, resp.Body)

	return resp.StatusCode, content.String(), nil
}

func (tc *testClient) AssertStatusCode(t *testing.T, method string, rawUrl string, expectedStatusCode int) {
	statusCode, _, err := tc.Request(method, rawUrl)
	if err != nil {
		t.Errorf("error while making %v %v: %v", method, rawUrl, err)
	}

	if statusCode != expectedStatusCode {
		t.Errorf("%v %v returned HTTP %v, expected HTTP %v", method, rawUrl, statusCode, expectedStatusCode)
	}
}

func TestWireguardInboundProxy(t *testing.T) {
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

	// setup "remote" wireguard peer
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

	// set up internal service
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello")
	}))
	defer internalServer.Close()
	log.Info("Internal server is up")

	// start network broker
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
			},
			Allowlist: []pkg.AllowlistItem{
				{
					URL:     internalServer.URL + "/allowed-get",
					Methods: pkg.ParseHttpMethods([]string{"GET"}),
				},
				{
					URL:     internalServer.URL + "/allowed-post",
					Methods: pkg.ParseHttpMethods([]string{"POST"}),
				},
				{
					URL:     internalServer.URL + "/allowed-path/:path",
					Methods: pkg.ParseHttpMethods([]string{"POST"}),
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
	log.Info("Network broker is up")

	// set up "remote" HTTP client
	remoteHttpClient := testClient{
		Client: &http.Client{
			Transport: &http.Transport{
				DialContext: remoteWireguard.DialContext,
			},
			Timeout: 1 * time.Second,
		},
		PeerAddress: clientWireguardAddress,
	}

	// it should proxy requests that match the allowlist
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/%v/allowed-get", clientWireguardAddress, internalServer.URL), 200)
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-post", clientWireguardAddress, internalServer.URL), 200)
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-path/foobar", clientWireguardAddress, internalServer.URL), 200)

	// it shouldnt decode urlencoded characters
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-path/%s", clientWireguardAddress, internalServer.URL, "foobar%2Fbla"), 200)

	// it should reject requests that don't match the allowlist
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-get", clientWireguardAddress, internalServer.URL), 403)
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/%v/allowed-post", clientWireguardAddress, internalServer.URL), 403)
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/https://google.com", clientWireguardAddress), 403)
}
