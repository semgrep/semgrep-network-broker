package pkg

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/mcuadros/go-defaults"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Base64String []byte

func (bs Base64String) String() string {
	return base64.StdEncoding.EncodeToString(bs)
}

func base64StringDecodeHook(
	f reflect.Type,
	t reflect.Type,
	data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}
	if t != reflect.TypeOf(Base64String(nil)) {
		return data, nil
	}

	bytes, err := base64.StdEncoding.DecodeString(data.(string))

	if err != nil {
		return nil, err
	}

	return Base64String(bytes), nil
}

type WireguardPeer struct {
	PublicKey                   Base64String `mapstructure:"publicKey" validate:"empty=false"`
	Endpoint                    string       `mapstructure:"endpoint"`
	resolvedEndpoint            string
	AllowedIps                  string `mapstructure:"allowedIps" validate:"format=cidr"`
	PersistentKeepaliveInterval int    `mapstructure:"persistentKeepaliveInterval" validate:"gt=0" default:"20"`
	DisablePersistentKeepalive  bool   `mapstructure:"disablePersistentKeepalive"`
}

type WireguardBase struct {
	LocalAddress string          `mapstructure:"localAddress" validate:"format=ip"`
	Dns          []string        `mapstructure:"dns" validate:"empty=true > format=ip"`
	Mtu          int             `mapstructure:"mtu" validate:"gte=0" default:"1420"`
	PrivateKey   Base64String    `mapstructure:"privateKey" validate:"empty=false"`
	ListenPort   int             `mapstructure:"listenPort" validate:"gte=0"`
	Peers        []WireguardPeer `mapstructure:"peers" validate:"empty=false"`
	Verbose      bool            `mapstructure:"verbose"`
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
	URL                   string            `mapstructure:"url"`
	Methods               HttpMethods       `mapstructure:"methods"`
	SetRequestHeaders     map[string]string `mapstructure:"setRequestHeaders"`
	RemoveResponseHeaders []string          `mapstructure:"removeResponseHeaders"`
}

type Allowlist []AllowlistItem

type LoggingConfig struct {
	SkipPaths []string `mapstructure:"skipPaths"`
}

type HeartbeatConfig struct {
	URL                       string `mapstructure:"url" validate:"format=url"`
	IntervalSeconds           int    `mapstructure:"intervalSeconds" validate:"gte=30" default:"60"`
	TimeoutSeconds            int    `mapstructure:"timeoutSeconds" validate:"gt=0" default:"5"`
	PanicAfterFailureCount    int    `mapstructure:"panicAfterFailureCount" validate:"gte=0"`
	FirstHeartbeatMustSucceed bool   `mapstructure:"firstHeartbeatMustSucceed"`
}

type InboundProxyConfig struct {
	Wireguard       WireguardBase   `mapstructure:"wireguard"`
	Allowlist       Allowlist       `mapstructure:"allowlist"`
	ProxyListenPort int             `mapstructure:"proxyListenPort" validate:"gte=0" default:"80"`
	Logging         LoggingConfig   `mapstructure:"logging"`
	Heartbeat       HeartbeatConfig `mapstructure:"heartbeat"`
}

type Config struct {
	Inbound InboundProxyConfig `mapstructure:"inbound"`
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
	return config, nil
}
