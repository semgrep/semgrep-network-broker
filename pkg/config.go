package pkg

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/bits-and-blooms/bitset"
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

func HttpMethodsToBitSet(methods []string) *bitset.BitSet {
	bitset := bitset.New(8)

	for _, method := range methods {
		bitset.Set(LookupHttpMethod(method))
	}

	return bitset
}

func httpMethodsDecodeHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.Slice {
		return data, nil
	}
	if f.Elem().Kind() != reflect.String {
		return data, nil
	}
	if t != reflect.TypeOf(bitset.BitSet{}) {
		return data, nil
	}

	return HttpMethodsToBitSet(data.([]string)), nil
}

type HttpMethods *bitset.BitSet

type AllowlistItem struct {
	URL                   string            `mapstructure:"url"`
	Methods               *bitset.BitSet    `mapstructure:"methods"`
	SetRequestHeaders     map[string]string `mapstructure:"setRequestHeaders"`
	RemoveResponseHeaders []string          `mapstructure:"removeResponseHeaders"`
}

type Allowlist []AllowlistItem

type InboundProxyConfig struct {
	Wireguard       WireguardBase `mapstructure:"wireguard"`
	Allowlist       Allowlist     `mapstructure:"allowlist"`
	ProxyListenPort int           `mapstructure:"proxyListenPort" validate:"gte=0" default:"80"`
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
