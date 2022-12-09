package pkg

type WireguardPeer struct {
	PublicKey                   string `mapstructure:"publicKey" validate:"empty=false"`
	Endpoint                    string `mapstructure:"endpoint"`
	resolvedEndpoint            string
	AllowedIps                  string `mapstructure:"allowedIps" validate:"format=cidr"`
	PersistentKeepaliveInterval int    `mapstructure:"persistentKeepaliveInterval" validate:"gte=0"`
}

type WireguardBase struct {
	LocalAddress string          `mapstructure:"localAddress" validate:"format=ip"`
	Dns          []string        `mapstructure:"dns" validate:"empty=true > format=ip"`
	Mtu          int             `mapstructure:"mtu" validate:"gte=0"`
	PrivateKey   string          `mapstructure:"privateKey" validate:"empty=false"`
	ListenPort   int             `mapstructure:"listenPort" validate:"gte=0"`
	Peers        []WireguardPeer `mapstructure:"peers" validate:"empty=false"`
}

type AllowlistItem struct {
	URL                   string            `mapstructure:"url"`
	AllowedMethods        []string          `mapstructure:"allowedMethods"`
	SetRequestHeaders     map[string]string `mapstructure:"setRequestHeaders"`
	RemoveResponseHeaders []string          `mapstructure:"removeResponseHeaders"`
}

type Allowlist []AllowlistItem

type InboundProxyConfig struct {
	Enabled   bool          `mapstructure:"enabled"`
	Metrics   bool          `mapstructure:"metrics"`
	Wireguard WireguardBase `mapstructure:"wireguard"`
	Allowlist Allowlist     `mapstructure:"allowlist"`
}

type OutboundProxyConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	BaseUrl  string `mapstructure:"baseUrl" validate:"empty=true | format=url"`
	Listen   string `mapstructure:"listen" validate:"empty=false"`
	AppToken string `mapstricture:"appToken"`
}

type Config struct {
	Debug    bool                `mapstructure:"debug"`
	Inbound  InboundProxyConfig  `mapstructure:"inbound"`
	Outbound OutboundProxyConfig `mapstructure:"outbound"`
}
