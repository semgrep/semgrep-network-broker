package it

import (
	"bytes"
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

	"github.com/gin-gonic/gin"
	"github.com/mcuadros/go-defaults"
	"github.com/semgrep/semgrep-network-broker/cmd"
	"github.com/semgrep/semgrep-network-broker/pkg"
	"github.com/stretchr/testify/assert"

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

func (tc *testClient) Request(req *http.Request) (int, string, error) {
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
	url, err := url.Parse(rawUrl)
	if err != nil {
		t.Errorf("error while making %v %v: %v", method, rawUrl, err)
	}

	req := &http.Request{
		Method: method,
		URL:    url,
	}

	if method != "GET" {
		req.Body = io.NopCloser(strings.NewReader("{\"foo\": 2}"))
	}

	statusCode, _, err := tc.Request(req)
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

	// set up internal service (the thing that the broker proxies to)
	internalServer := gin.Default()

	// we want this proxy to be transparent, so don't un-escape characters in the URL
	internalServer.UseRawPath = true
	internalServer.UnescapePathValues = false

	internalServer.Any("/allowed-get", func(ctx *gin.Context) {
		ctx.String(200, "Hello")
	})
	internalServer.Any("/unallowed-get", func(ctx *gin.Context) {
		ctx.String(200, "Hello")
	})
	internalServer.Any("/allowed-post", func(ctx *gin.Context) {
		ctx.String(200, "Hello")
	})
	internalServer.Any("/allowed-path/:path", func(ctx *gin.Context) {
		ctx.String(200, "Hello %v", ctx.GetString("path"))
	})

	internalListener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Errorf("Failed to start internal listener: %v", err)
	}
	defer internalListener.Close()
	go internalServer.RunListener(internalListener)
	log.Info("Internal server is up")

	internalServerBaseUrl := fmt.Sprintf("http://%v", internalListener.Addr().String())

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
					URL:     internalServerBaseUrl + "/allowed-get",
					Methods: pkg.ParseHttpMethods([]string{"GET"}),
				},
				{
					URL:     internalServerBaseUrl + "/allowed-post",
					Methods: pkg.ParseHttpMethods([]string{"POST"}),
				},
				{
					URL:     internalServerBaseUrl + "/allowed-path/:path",
					Methods: pkg.ParseHttpMethods([]string{"POST"}),
				},
			},
			Heartbeat: pkg.HeartbeatConfig{
				URL: fmt.Sprintf("http://[%v]/ping", gatewayWireguardAddress),
			},
			Logging: pkg.LoggingConfig{
				LogRequestBody:  true,
				LogResponseBody: true,
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
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/%v/allowed-get", clientWireguardAddress, internalServerBaseUrl), 200)
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-post", clientWireguardAddress, internalServerBaseUrl), 200)
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-path/foobar", clientWireguardAddress, internalServerBaseUrl), 200)

	// it should pass along all query params
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/%v/allowed-get?foo=bar", clientWireguardAddress, internalServerBaseUrl), 200)

	// it shouldnt decode urlencoded characters
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-path/%s", clientWireguardAddress, internalServerBaseUrl, "foobar%2Fbla"), 200)

	// it should reject requests that don't match the allowlist
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/unallowed-get", clientWireguardAddress, internalServerBaseUrl), 403)
	remoteHttpClient.AssertStatusCode(t, "POST", fmt.Sprintf("http://[%v]/proxy/%v/allowed-get", clientWireguardAddress, internalServerBaseUrl), 403)
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/%v/allowed-post", clientWireguardAddress, internalServerBaseUrl), 403)
	remoteHttpClient.AssertStatusCode(t, "GET", fmt.Sprintf("http://[%v]/proxy/https://google.com", clientWireguardAddress), 403)
}

func TestRelay(t *testing.T) {
	assert := assert.New(t)

	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Server1")
	}))
	defer internalServer.Close()

	internalServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Server2")
	}))
	defer internalServer2.Close()

	relayPort := mustGetFreePort()

	relayConfig := &pkg.Config{
		Outbound: pkg.OutboundProxyConfig{
			Relay: map[string]pkg.FilteredRelayConfig{
				"always-succeed": {
					DestinationURL: internalServer.URL,
				},
				"post-jsonpath-foo-bar": {
					DestinationURL: internalServer.URL,
					JSONPath:       "$.foo",
					Equals:         []string{"bar"},
				},
				"github-pr-comment-with-fallback": {
					DestinationURL: internalServer.URL,
					JSONPath:       "$.comment.body",
					Contains:       []string{"/semgrep"},
					HeaderEquals: map[string]string{
						"X-GitHub-Event": "pull_request_review_comment",
					},
					AdditionalConfigs: []pkg.FilteredRelayConfig{
						{
							DestinationURL: internalServer2.URL,
							HeaderNotEquals: map[string]string{
								"X-GitHub-Event": "pull_request_review_comment",
							},
						},
					},
				},
			},
			ListenPort: relayPort,
		},
	}

	if err := relayConfig.Outbound.Start(); err != nil {
		panic(err)
	}

	buildUrl := func(relayName string) *url.URL {
		url, err := url.Parse(fmt.Sprintf("http://localhost:%v/relay/%v", relayPort, relayName))
		if err != nil {
			panic(err)
		}
		return url
	}

	var req *http.Request
	var resp *http.Response
	var bodyBuilder *strings.Builder

	resp, _ = http.Get(buildUrl("not-real").String())
	assert.Equal(400, resp.StatusCode, "Non-existent relay should 400")

	resp, _ = http.Get(buildUrl("always-succeed").String())
	assert.Equal(200, resp.StatusCode, "Always-succeed should 200")

	resp, _ = http.Post(buildUrl("post-jsonpath-foo-bar").String(), "application/json", bytes.NewBufferString("{\"foo\": \"bar\"}"))
	assert.Equal(200, resp.StatusCode, "foo: bar should return 200")
	assert.Equal("1", resp.Header.Get("X-Semgrep-Network-Broker-Relay-Match"), "foo: bar should be a relay match")

	resp, _ = http.Post(buildUrl("post-jsonpath-foo-bar").String(), "application/json", bytes.NewBufferString("{\"foo\": \"baz\"}"))
	assert.Equal(200, resp.StatusCode, "foo: baz should return 200")
	assert.Equal("0", resp.Header.Get("X-Semgrep-Network-Broker-Relay-Match"), "foo: baz should not be a relay match")

	req = &http.Request{
		Method: "POST",
		URL:    buildUrl("github-pr-comment-with-fallback"),
		Header: http.Header{
			"X-GitHub-Event": []string{"pull_request_review_comment"},
		},
		Body: io.NopCloser(bytes.NewBufferString("{\"comment\": {\"body\": \"hello\"}}")),
	}
	resp, _ = http.DefaultClient.Do(req)
	assert.Equal(200, resp.StatusCode, "non-semgrep comment should return 200")
	assert.Equal("0", resp.Header.Get("X-Semgrep-Network-Broker-Relay-Match"), "non-semgrep comment should not match")

	req = &http.Request{
		Method: "POST",
		URL:    buildUrl("github-pr-comment-with-fallback"),
		Header: http.Header{
			"X-GitHub-Event": []string{"pull_request_review_comment"},
		},
		Body: io.NopCloser(bytes.NewBufferString("{\"comment\": {\"body\": \"/semgrep test\"}}")),
	}
	resp, _ = http.DefaultClient.Do(req)
	buf := new(strings.Builder)
	io.Copy(buf, resp.Body)
	assert.Equal(200, resp.StatusCode, "semgrep comment should return 200")
	assert.Equal("1", resp.Header.Get("X-Semgrep-Network-Broker-Relay-Match"), "semgrep comment should match")
	assert.Equal("Server1", buf.String(), "semgrep comment should be relayed to Server1")

	req = &http.Request{
		Method: "POST",
		URL:    buildUrl("github-pr-comment-with-fallback"),
		Header: http.Header{
			"X-GitHub-Event": []string{"issue"},
		},
		Body: io.NopCloser(bytes.NewBufferString("{\"foo\": \"bar\"}}")),
	}
	resp, _ = http.DefaultClient.Do(req)
	bodyBuilder = new(strings.Builder)
	io.Copy(bodyBuilder, resp.Body)
	assert.Equal(200, resp.StatusCode, "other event should return 200")
	assert.Equal("1", resp.Header.Get("X-Semgrep-Network-Broker-Relay-Match"), "other event should match")
	assert.Equal("Server2", bodyBuilder.String(), "other event should be relayed to Server2")
}
