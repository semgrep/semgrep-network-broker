package pkg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/mcuadros/go-defaults"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Base64String []byte

func (bs Base64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(bs))
}

type SensitiveBase64String []byte

const RedactedString = "REDACTED"

func (sbs SensitiveBase64String) String() string {
	return RedactedString
}

func (sbs SensitiveBase64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(sbs.String())
}

var base64StringType = reflect.TypeOf(Base64String(nil))
var sensitiveBase64StringType = reflect.TypeOf(SensitiveBase64String(nil))

func base64StringDecodeHook(
	f reflect.Type,
	t reflect.Type,
	data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}

	if t != base64StringType && t != sensitiveBase64StringType {
		return data, nil
	}

	bytes, err := base64.StdEncoding.DecodeString(data.(string))

	if err != nil {
		return nil, err
	}

	if t == sensitiveBase64StringType {
		return SensitiveBase64String(bytes), err
	} else {
		return Base64String(bytes), err
	}
}

type WireguardPeer struct {
	resolvedEndpoint            string
	PublicKey                   Base64String `mapstructure:"publicKey" json:"publicKey" validate:"empty=false"`
	Endpoint                    string       `mapstructure:"endpoint" json:"endpoint"`
	AllowedIps                  string       `mapstructure:"allowedIps" json:"allowedIps" validate:"format=cidr"`
	PersistentKeepaliveInterval int          `mapstructure:"persistentKeepaliveInterval" json:"persistentKeepaliveInterval" validate:"gt=0" default:"20"`
	DisablePersistentKeepalive  bool         `mapstructure:"disablePersistentKeepalive" json:"disablePersistentKeepalive"`
}

type WireguardBase struct {
	LocalAddress string                `mapstructure:"localAddress" json:"localAddress" validate:"format=ip"`
	Dns          []string              `mapstructure:"dns" json:"dns" validate:"empty=true > format=ip"`
	Mtu          int                   `mapstructure:"mtu" json:"mtu" validate:"gte=0" default:"1420"`
	PrivateKey   SensitiveBase64String `mapstructure:"privateKey" json:"privateKey" validate:"empty=false"`
	ListenPort   int                   `mapstructure:"listenPort" json:"listenPort" validate:"gte=0"`
	Peers        []WireguardPeer       `mapstructure:"peers" json:"peers" validate:"empty=false"`
	Verbose      bool                  `mapstructure:"verbose" json:"verbose"`
}

type BitTester interface {
	Test(i uint) bool
}

type BitSet uint16

func (bs BitSet) Test(i uint) bool {
	return bs&(1<<i) != 0
}

func (bs *BitSet) Set(i uint) error {
	if i >= 16 {
		return fmt.Errorf("bitset limited to 16 bits")
	}
	*bs = *bs | (1 << i)
	return nil
}

type HttpMethods BitSet

func (methods HttpMethods) Test(i uint) bool {
	return BitSet(methods).Test(i)
}

const (
	MethodUnknown uint = iota
	MethodGet
	MethodHead
	MethodPost
	MethodPut
	MethodPatch
	MethodDelete
	MethodConnect
	MethodOptions
	MethodTrace
)

func LookupHttpMethod(method string) uint {
	switch strings.ToUpper(method) {
	case "GET":
		return MethodGet
	case "HEAD":
		return MethodHead
	case "POST":
		return MethodPost
	case "PUT":
		return MethodPut
	case "PATCH":
		return MethodPatch
	case "DELETE":
		return MethodDelete
	case "CONNECT":
		return MethodConnect
	case "TRACE":
		return MethodTrace
	}
	return MethodUnknown
}

func ParseHttpMethods(methods []string) HttpMethods {
	bs := BitSet(0)

	for _, method := range methods {
		bs.Set(LookupHttpMethod(method))
	}

	return HttpMethods(bs)
}

func httpMethodsDecodeHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.Slice {
		return data, nil
	}
	if t != reflect.TypeOf(HttpMethods(0)) {
		return data, nil
	}
	if f.Elem().Kind() == reflect.String {
		return ParseHttpMethods(data.([]string)), nil
	}

	methods := make([]string, len(data.([]interface{})))
	for i, method := range data.([]interface{}) {
		methodString, ok := method.(string)
		if !ok {
			return nil, fmt.Errorf("item at index %v is not a string", i)
		}
		methods = append(methods, methodString)
	}

	return ParseHttpMethods(methods), nil
}

type AllowlistItem struct {
	URL                   string            `mapstructure:"url" json:"url"`
	Methods               HttpMethods       `mapstructure:"methods" json:"methods"`
	SetRequestHeaders     map[string]string `mapstructure:"setRequestHeaders" json:"setRequestHeaders"`
	RemoveResponseHeaders []string          `mapstructure:"removeResponseHeaders" json:"removeRequestHeaders"`
}

type Allowlist []AllowlistItem

type LoggingConfig struct {
	SkipPaths []string `mapstructure:"skipPaths"`
}

type HeartbeatConfig struct {
	URL                       string `mapstructure:"url" json:"url" validate:"format=url"`
	IntervalSeconds           int    `mapstructure:"intervalSeconds" json:"intervalSeconds" validate:"gte=30" default:"60"`
	TimeoutSeconds            int    `mapstructure:"timeoutSeconds" json:"timeoutSeconds" validate:"gt=0" default:"5"`
	PanicAfterFailureCount    int    `mapstructure:"panicAfterFailureCount" json:"panicAfterFailureCount" validate:"gte=0"`
	FirstHeartbeatMustSucceed bool   `mapstructure:"firstHeartbeatMustSucceed" json:"firstHeartbeatMustSucceed"`
}

type GitHub struct {
	BaseURL string `mapstructure:"baseUrl" json:"baseUrl"`
	Token   string `mapstructure:"token" json:"token"`
}

type GitLab struct {
	BaseURL string `mapstructure:"baseUrl" json:"baseUrl"`
	Token   string `mapstructure:"token" json:"token"`
}

type InboundProxyConfig struct {
	Wireguard       WireguardBase   `mapstructure:"wireguard" json:"wireguard"`
	Allowlist       Allowlist       `mapstructure:"allowlist" json:"allowlist"`
	ProxyListenPort int             `mapstructure:"proxyListenPort" json:"proxyListenPort" validate:"gte=0" default:"80"`
	Logging         LoggingConfig   `mapstructure:"logging" json:"logging"`
	Heartbeat       HeartbeatConfig `mapstructure:"heartbeat" json:"heartbeat"`
	GitHub          *GitHub         `mapstructure:"github" json:"github"`
	GitLab          *GitLab         `mapstructure:"gitlab" json:"gitlab"`
}

type FilteredRelayConfig struct {
	DestinationURL string   `mapstructure:"destinationUrl"`
	JSONPath       string   `mapstructure:"jsonPath"`
	Contains       []string `mapstructure:"contains"`
	Equals         []string `mapstructure:"equals"`
	HasPrefix      []string `mapstructure:"hasPrefix"`
}

type OutboundProxyConfig struct {
	Relay      map[string]FilteredRelayConfig `mapstructure:"relay" json:"relay"`
	ListenPort int                            `mapstructure:"listenPort" json:"listenPort" validate:"gte=0" default:"8080"`
}

type Config struct {
	Inbound  InboundProxyConfig  `mapstructure:"inbound" json:"inbound"`
	Outbound OutboundProxyConfig `mapstructure:"outbound" json:"outbound"`
}

func LoadConfig(configFiles []string) (*Config, error) {
	config := new(Config)
	for i := range configFiles {
		viper.SetConfigFile(configFiles[i])
		if err := viper.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("failed to merge config file '%s': %v", configFiles[i], err)
		}
	}
	if err := viper.Unmarshal(config, func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(base64StringDecodeHook, httpMethodsDecodeHook)
	}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	defaults.SetDefaults(config)

	if config.Inbound.GitHub != nil {
		gitHub := config.Inbound.GitHub

		gitHubBaseUrl, err := url.Parse(gitHub.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse github base URL: %v", err)
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("Bearer %v", gitHub.Token),
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// repo info
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// PR info
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post PR comment
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/:number/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// post issue comment
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/issues/:number/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			})
	}

	if config.Inbound.GitLab != nil {
		gitLab := config.Inbound.GitLab

		gitLabBaseUrl, err := url.Parse(gitLab.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gitlab base URL: %v", err)
		}

		headers := map[string]string{
			"PRIVATE-TOKEN": gitLab.Token,
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// repo info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// MR info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// MR versions
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/versions").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST"}),
				SetRequestHeaders: headers,
			},
			// update MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note").String(),
				Methods:           ParseHttpMethods([]string{"PUT"}),
				SetRequestHeaders: headers,
			},
			// resolve MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion").String(),
				Methods:           ParseHttpMethods([]string{"PUT"}),
				SetRequestHeaders: headers,
			},
		)
	}

	return config, nil
}
