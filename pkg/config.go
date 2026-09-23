package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/go-viper/mapstructure/v2"
	"github.com/mcuadros/go-defaults"
	"github.com/spf13/viper"
)

const SemgrepHostnameEnvVar = "SEMGREP_HOSTNAME"
const DefaultSemgrepHostname = "semgrep.dev"
const SemgrepWireguardPeerFormat = "wireguard.%s:51820"
const PrivateKeyEnvVar = "SEMGREP_NETWORK_BROKER_PRIVATE_KEY"
const PrivateKeyPathEnvVar = PrivateKeyEnvVar + "_PATH"
const privateKeyConfigKey = "inbound.wireguard.privateKey"

const WireguardPrivateKeySize = 32 // bytes; 44 characters in base64

// Accepts any whole multiple of the key size so legacy concatenated keys (see GenerateConfig) still load.
// An empty key is caught by struct validation at tunnel start.
func validateWireguardPrivateKey(key SensitiveBase64String, source string) error {
	if len(key)%WireguardPrivateKeySize != 0 {
		return fmt.Errorf("invalid WireGuard private key from %s: expected 32 bytes (44 base64 characters), got %d bytes. Generate a key with 'semgrep-network-broker genkey'", source, len(key))
	}
	return nil
}

// Returns the base64 private key from the environment (if any) and a description of its source.
// The plain variable wins over _PATH. Whitespace is trimmed so files with a trailing newline work.
func loadPrivateKeyFromEnv() (string, string, error) {
	if value := strings.TrimSpace(os.Getenv(PrivateKeyEnvVar)); value != "" {
		return value, PrivateKeyEnvVar + " environment variable", nil
	}

	path := os.Getenv(PrivateKeyPathEnvVar)
	if path == "" {
		return "", "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("failed to read private key file %q named by %s: %w", path, PrivateKeyPathEnvVar, err)
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", "", fmt.Errorf("private key file %q named by %s is empty", path, PrivateKeyPathEnvVar)
	}

	return value, fmt.Sprintf("file %q (%s)", path, PrivateKeyPathEnvVar), nil
}

func getSemgrepHostname() string {
	hostname := os.Getenv(SemgrepHostnameEnvVar)
	if hostname == "" {
		hostname = DefaultSemgrepHostname
	}
	return hostname
}

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
	LocalAddress                 string                `mapstructure:"localAddress" json:"localAddress" validate:"format=ip"`
	Dns                          []string              `mapstructure:"dns" json:"dns" validate:"empty=true > format=ip"`
	Mtu                          int                   `mapstructure:"mtu" json:"mtu" validate:"gte=0" default:"1320"`
	PrivateKey                   SensitiveBase64String `mapstructure:"privateKey" json:"privateKey" validate:"empty=false"`
	ListenPort                   int                   `mapstructure:"listenPort" json:"listenPort" validate:"gte=0"`
	Peers                        []WireguardPeer       `mapstructure:"peers" json:"peers" validate:"empty=false"`
	Verbose                      bool                  `mapstructure:"verbose" json:"verbose"`
	DisablePeerSettingsDnsLookup bool                  `mapstructure:"disablePeerSettingsDnsLookup" json:"disablePeerSettingsDnsLookup"`
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
	LogRequestBody        bool              `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders     bool              `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody       bool              `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders    bool              `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
}

type Allowlist []AllowlistItem

type LoggingConfig struct {
	SkipPaths          []string `mapstructure:"skipPaths" json:"skipPaths"`
	LogRequestBody     bool     `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders  bool     `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody    bool     `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders bool     `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
}

type HeartbeatConfig struct {
	URL                       string `mapstructure:"url" json:"url" validate:"format=url"`
	IntervalSeconds           int    `mapstructure:"intervalSeconds" json:"intervalSeconds" validate:"gte=30" default:"60"`
	TimeoutSeconds            int    `mapstructure:"timeoutSeconds" json:"timeoutSeconds" validate:"gt=0" default:"5"`
	PanicAfterFailureCount    int    `mapstructure:"panicAfterFailureCount" json:"panicAfterFailureCount" validate:"gte=0"`
	FirstHeartbeatMustSucceed bool   `mapstructure:"firstHeartbeatMustSucceed" json:"firstHeartbeatMustSucceed"`
}

type GitHub struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type GitLab struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type BitBucket struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type AzureDevOps struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type HttpClientConfig struct {
	AdditionalCACerts []string `mapstructure:"additionalCACerts" json:"additionalCACerts"`
	TlsMinVersion     string   `mapstructure:"tlsMinVersion" json:"tlsMinVersion" validate:"one_of=1.2,1.3" default:"1.3"`
}

type InboundProxyConfig struct {
	Wireguard       WireguardBase    `mapstructure:"wireguard" json:"wireguard"`
	Allowlist       Allowlist        `mapstructure:"allowlist" json:"allowlist"`
	ProxyListenPort int              `mapstructure:"proxyListenPort" json:"proxyListenPort" validate:"gte=0" default:"80"`
	Logging         LoggingConfig    `mapstructure:"logging" json:"logging"`
	Heartbeat       HeartbeatConfig  `mapstructure:"heartbeat" json:"heartbeat"`
	SCMs            []SCM            `mapstructure:"scms" json:"scms"`
	GitHub          *GitHub          `mapstructure:"github" json:"github"`
	GitLab          *GitLab          `mapstructure:"gitlab" json:"gitlab"`
	BitBucket       *BitBucket       `mapstructure:"bitbucket" json:"bitbucket"`
	AzureDevOps     *AzureDevOps     `mapstructure:"azuredevops" json:"azuredevops"`
	HttpClient      HttpClientConfig `mapstructure:"httpClient" json:"httpClient"`
}

type FilteredRelayConfig struct {
	DestinationURL    string                `mapstructure:"destinationUrl"`
	JSONPath          string                `mapstructure:"jsonPath"`
	Contains          []string              `mapstructure:"contains"`
	Equals            []string              `mapstructure:"equals"`
	HasPrefix         []string              `mapstructure:"hasPrefix"`
	HeaderEquals      map[string]string     `mapstructure:"headerEquals"`
	HeaderNotEquals   map[string]string     `mapstructure:"headerNotEquals"`
	AdditionalConfigs []FilteredRelayConfig `mapstructure:"additionalConfigs"` // this is awful, but we can refactor this in the near future

	LogRequestBody     bool `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders  bool `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody    bool `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders bool `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
}

type OutboundProxyConfig struct {
	Relay      map[string]FilteredRelayConfig `mapstructure:"relay" json:"relay"`
	Logging    LoggingConfig                  `mapstructure:"logging" json:"logging"`
	ListenPort int                            `mapstructure:"listenPort" json:"listenPort" validate:"gte=0" default:"8080"`
}

type MetricsConfig struct {
	Disabled                      bool   `mapstructure:"disabled" json:"disabled"`
	Addr                          string `mapstructure:"addr" json:"addr" default:":9000"`
	HealthcheckGracePeriodSeconds int    `mapstructure:"healthcheckGracePeriodSeconds" json:"healthcheckGracePeriodSeconds" validate:"gte=0" default:"10"`
}

type Config struct {
	Inbound  InboundProxyConfig  `mapstructure:"inbound" json:"inbound"`
	Outbound OutboundProxyConfig `mapstructure:"outbound" json:"outbound"`
	Metrics  MetricsConfig       `mapstructure:"metrics" json:"metrics"`
}

func LoadConfig(configFiles []string, deploymentId int) (*Config, error) {
	hostname := getSemgrepHostname()

	config := new(Config)

	var scms []map[string]any

	// Step 0: Set default wireguard peer
	config.Inbound.Wireguard.Peers = []WireguardPeer{
		{
			Endpoint: fmt.Sprintf(SemgrepWireguardPeerFormat, hostname),
		},
	}

	privateKeySource := "config" // for error messages

	// Step 1: Apply config values encoded in broker token (if provided)
	tokenString, err := LoadTokenFromEnv()
	if err != nil {
		return config, fmt.Errorf("failed to load token: %v", err)
	}

	if tokenString != "" {
		token, err := ParseBrokerToken(tokenString)
		if err != nil {
			return config, fmt.Errorf("failed to parse token: %v", err)
		}

		config.Inbound.Wireguard.LocalAddress = token.WireguardCredential.LocalAddress
		config.Inbound.Wireguard.PrivateKey = token.WireguardCredential.PrivateKey
		privateKeySource = "broker token"
		log.WithField("source", "broker_token").Info("Loaded WireGuard private key from broker token")
	}

	// Step 2: Apply config values from semgrep.dev/api/broker/{deployment_id}/default-config, if a deployment ID is provided
	// NOTE: we will be phasing this out in favor of retrieving default configs from the broker gateway
	if deploymentId > 0 {
		url := url.URL{
			Scheme: "https",
			Host:   hostname,
			Path:   fmt.Sprintf("/api/broker/%d/default-config", deploymentId),
		}

		resp, err := http.Get(url.String())
		if err != nil {
			return nil, fmt.Errorf("failed to request default broker config from %v: %v", hostname, err)
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("failed to request default config from %s: HTTP %v", url.String(), resp.StatusCode)
		}

		f, err := os.CreateTemp("", "default-config*.json")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file to store default config: %v", err)
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()

		io.Copy(f, resp.Body)
		defer resp.Body.Close()

		if err := mergeConfigFile(f.Name(), &scms); err != nil {
			return nil, err
		}
	}

	// Step 3: Load config files passed via command line
	for i := range configFiles {
		if err := mergeConfigFile(configFiles[i], &scms); err != nil {
			return nil, err
		}
	}

	// Step 4: Apply private key from the environment if provided (takes precedence over all other sources).
	// Set on viper before unmarshalling so a stale or malformed config file key is never decoded.
	privateKeyEnv, privateKeyEnvSource, err := loadPrivateKeyFromEnv()
	if err != nil {
		return nil, err
	}
	if privateKeyEnv != "" {
		if viper.IsSet(privateKeyConfigKey) {
			log.WithField("source", "environment_variable").Warnf("%s overriding private key from config file", privateKeyEnvSource)
		} else if len(config.Inbound.Wireguard.PrivateKey) > 0 {
			log.WithField("source", "environment_variable").Warnf("%s overriding private key from %s", privateKeyEnvSource, privateKeySource)
		}

		if _, err := base64.StdEncoding.DecodeString(privateKeyEnv); err != nil {
			return nil, fmt.Errorf("failed to decode private key from %s: %v", privateKeyEnvSource, err)
		}

		viper.Set(privateKeyConfigKey, privateKeyEnv)
		privateKeySource = privateKeyEnvSource
		log.WithField("source", "environment_variable").Infof("Loaded WireGuard private key from %s", privateKeyEnvSource)
	} else if viper.IsSet(privateKeyConfigKey) {
		privateKeySource = "config file"
	}

	if err := viper.Unmarshal(config, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(base64StringDecodeHook, httpMethodsDecodeHook))); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Validate the key length regardless of source; otherwise a bad key only surfaces as a panic in GenerateConfig
	if err := validateWireguardPrivateKey(config.Inbound.Wireguard.PrivateKey, privateKeySource); err != nil {
		return nil, err
	}

	config.Inbound.SCMs = nil
	if err := decodeSCMs(scms, &config.Inbound.SCMs); err != nil {
		return nil, fmt.Errorf("failed to decode %s: %v", scmsConfigKey, err)
	}

	if err := validateSCMs(&config.Inbound); err != nil {
		return nil, err
	}

	// Step 5: Resolve TXT record(s) of wireguard peers, fill in config values if not set in a config file
	if !config.Inbound.Wireguard.DisablePeerSettingsDnsLookup {
		for i := range config.Inbound.Wireguard.Peers {
			peer := &config.Inbound.Wireguard.Peers[i]

			endpoint := peer.Endpoint
			if i := strings.Index(endpoint, ":"); i >= 0 {
				endpoint = endpoint[0:i]
			}

			if net.ParseIP(endpoint) != nil {
				continue // cant look up TXT record for IPs
			}

			logger := log.WithField("endpoint", endpoint)

			records, err := net.LookupTXT(endpoint)
			if err != nil {
				var dnsError *net.DNSError
				if errors.As(err, &dnsError) && dnsError.IsNotFound {
					logger.WithError(dnsError).Warn("txt_lookup.failed")
				} else {
					return nil, fmt.Errorf("failed to lookup TXT records for %v: %w", endpoint, err)
				}
			}

			for _, record := range records {
				i := strings.Index(record, "=")
				if i < 0 {
					continue // skip any records that arent key=value formatted
				}
				key, value := record[0:i], record[i+1:]
				switch key {
				case "wireguardAllowedIps":
					if peer.AllowedIps == "" {
						peer.AllowedIps = value
					}
				case "wireguardPublicKey":
					if peer.PublicKey == nil {
						decoded_value, err := base64.StdEncoding.DecodeString(value)
						if err != nil {
							return nil, fmt.Errorf("failed to decode pubkey %v: %w", value, err)
						}
						peer.PublicKey = Base64String(decoded_value)
					}
				case "heartbeat":
					if config.Inbound.Heartbeat.URL == "" {
						config.Inbound.Heartbeat.URL = value
					}
				default:
					logger.WithField("record_key", key).WithField("record_value", value).Warn("txt_lookup.unrecognized_key")
				}
			}
		}
	}

	// Step 6: Apply default values to any remaining unset config fields
	defaults.SetDefaults(config)

	if err := PopulateAllowLists(config); err != nil {
		return nil, fmt.Errorf("failed to populate allowlists: %v", err)
	}

	return config, nil
}

const scmsConfigKey = "inbound.scms"

// mergeConfigFile merges path into the shared viper config, first setting aside
// inbound.scms. viper replaces slices on merge instead of combining them, so a list
// declared in two files would keep only the last file's entries.
func mergeConfigFile(path string, scms *[]map[string]any) error {
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file '%s': %v", path, err)
	}

	if value := v.Get(scmsConfigKey); value != nil {
		raw, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s: %s must be a list", path, scmsConfigKey)
		}

		for i, item := range raw {
			entry, ok := item.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: %s[%d] is not a mapping", path, scmsConfigKey, i)
			}
			mergeSCMEntry(scms, entry)
		}
	}

	viper.SetConfigFile(path)
	if err := viper.MergeInConfig(); err != nil {
		return fmt.Errorf("failed to merge config file '%s': %v", path, err)
	}

	return nil
}

// An SCM is identified by its type and base URL, both of which a config states anyway, so
// one file can amend another's entry without anyone naming it. Scheme and host are
// compared case-insensitively per RFC 3986. The path keeps its case but is cleaned the way
// url.URL.JoinPath cleans it, because that is what the allowlist builders call: two base
// URLs that generate the same rules have to be the same SCM here, or one entry silently
// shadows the other and the more permissive rules win. Map keys are lowercase because
// viper has already flattened their case.
func scmKey(scmType, baseURL string) string {
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)

		// JoinPath resolves dot segments but keeps a trailing slash, which the builders
		// drop once they append an endpoint.
		canonical := parsed.JoinPath()
		canonical.Path = strings.TrimSuffix(canonical.Path, "/")
		canonical.RawPath = strings.TrimSuffix(canonical.RawPath, "/")
		baseURL = canonical.String()
	}

	return strings.ToLower(scmType) + " " + baseURL
}

func scmEntryKey(entry map[string]any) string {
	scmType, _ := entry["type"].(string)
	baseURL, _ := entry["baseurl"].(string)

	return scmKey(scmType, baseURL)
}

// Entries stay maps until every file is read: a decoded struct cannot tell
// allowCodeAccess:false from an absent key, so merging structs would leave no way to
// clear the flag in a later file.
func mergeSCMEntry(scms *[]map[string]any, incoming map[string]any) {
	key := scmEntryKey(incoming)
	for _, existing := range *scms {
		if scmEntryKey(existing) == key {
			maps.Copy(existing, incoming)
			return
		}
	}

	*scms = append(*scms, incoming)
}

// ErrorUnused rejects keys the SCM struct does not define. Without it a misspelled
// allowCodeAccess merges in as a stray key and silently leaves the real flag as an
// earlier file set it, which is the fail-open case the map-based merge exists to avoid.
func decodeSCMs(raw []map[string]any, out *[]SCM) error {
	if len(raw) == 0 {
		return nil
	}

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:      out,
		ErrorUnused: true,
		DecodeHook:  mapstructure.ComposeDecodeHookFunc(base64StringDecodeHook, httpMethodsDecodeHook),
	})
	if err != nil {
		return err
	}

	return decoder.Decode(raw)
}

// baseUrl is required because it is half the identity of an entry: entries without one
// would all collapse onto each other.
//
// A single-provider key naming the same SCM as a list entry is rejected rather than
// resolved. The two would otherwise generate separate allowlists and the more permissive
// allowCodeAccess would win, so a config saying false in one place and true in the other
// grants code access.
func validateSCMs(config *InboundProxyConfig) error {
	keys := make(map[string]struct{}, len(config.SCMs))

	for i, scm := range config.SCMs {
		switch scm.Type {
		case SCMTypeGitHub, SCMTypeGitLab, SCMTypeBitBucket, SCMTypeAzureDevOps:
		default:
			return fmt.Errorf("%s[%d]: unknown type %q", scmsConfigKey, i, scm.Type)
		}

		if scm.BaseURL == "" {
			return fmt.Errorf("%s[%d]: baseUrl is required", scmsConfigKey, i)
		}

		keys[scmKey(string(scm.Type), scm.BaseURL)] = struct{}{}
	}

	checkOverlap := func(field string, scmType SCMType, baseURL string) error {
		if _, ok := keys[scmKey(string(scmType), baseURL)]; !ok {
			return nil
		}

		return fmt.Errorf("inbound.%s and %s both configure %v %v: declare it in one place",
			field, scmsConfigKey, scmType, baseURL)
	}

	if config.GitHub != nil {
		if err := checkOverlap("github", SCMTypeGitHub, config.GitHub.BaseURL); err != nil {
			return err
		}
	}
	if config.GitLab != nil {
		if err := checkOverlap("gitlab", SCMTypeGitLab, config.GitLab.BaseURL); err != nil {
			return err
		}
	}
	if config.BitBucket != nil {
		if err := checkOverlap("bitbucket", SCMTypeBitBucket, config.BitBucket.BaseURL); err != nil {
			return err
		}
	}
	if config.AzureDevOps != nil {
		if err := checkOverlap("azuredevops", SCMTypeAzureDevOps, config.AzureDevOps.BaseURL); err != nil {
			return err
		}
	}

	return validateGitRuleOrigins(config)
}

// The git smart transfer protocol serves paths off the host root, so these types build
// their clone rules from scheme and host and drop the base URL path. Azure DevOps keeps
// the path in its clone rules and returns "", meaning its instances never collide.
func gitRuleOrigin(typ SCMType, baseURL string) string {
	switch typ {
	case SCMTypeGitHub, SCMTypeGitLab, SCMTypeBitBucket:
	default:
		return ""
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return ""
	}

	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}

// Two instances of one type on a single host generate identical clone rules, and
// Allowlist.FindMatch returns the first match, so the first entry's rules and token would
// serve both. Instances without code access generate no clone rules, so a host where no
// instance enables it has nothing to collide.
func validateGitRuleOrigins(config *InboundProxyConfig) error {
	instances := config.scmInstances()

	for i, a := range instances {
		origin := gitRuleOrigin(a.typ, a.baseURL)
		if origin == "" {
			continue
		}

		for _, b := range instances[i+1:] {
			if b.typ != a.typ || gitRuleOrigin(b.typ, b.baseURL) != origin {
				continue
			}
			if !a.allowCodeAccess && !b.allowCodeAccess {
				continue
			}

			return fmt.Errorf("%v instances %v and %v share host %v: git clone rules are built from the host alone, so both would generate the same rules and the first entry's token would serve both. Give each instance its own host, or leave allowCodeAccess off on every instance on this host",
				a.typ, a.baseURL, b.baseURL, origin)
		}
	}

	return nil
}

type SCMType string

const (
	SCMTypeGitHub      SCMType = "github"
	SCMTypeGitLab      SCMType = "gitlab"
	SCMTypeBitBucket   SCMType = "bitbucket"
	SCMTypeAzureDevOps SCMType = "azuredevops"
)

// SCM is one entry of inbound.scms. Several entries may share a Type, which is what the
// single-provider keys cannot express.
type SCM struct {
	Type            SCMType `mapstructure:"type" json:"type"`
	BaseURL         string  `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string  `mapstructure:"token" json:"token"`
	AllowCodeAccess bool    `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type scmInstance struct {
	typ             SCMType
	baseURL         string
	token           string
	allowCodeAccess bool
}

// Must not mutate config: PopulateAllowLists runs more than once against the same config
// and appends to the allowlist each time. Order sets allowlist precedence, since
// Allowlist.FindMatch returns the first match.
func (config *InboundProxyConfig) scmInstances() []scmInstance {
	var instances []scmInstance

	for _, scm := range config.SCMs {
		instances = append(instances, scmInstance{
			typ:             scm.Type,
			baseURL:         scm.BaseURL,
			token:           scm.Token,
			allowCodeAccess: scm.AllowCodeAccess,
		})
	}

	if config.GitHub != nil {
		instances = append(instances, scmInstance{
			typ:             SCMTypeGitHub,
			baseURL:         config.GitHub.BaseURL,
			token:           config.GitHub.Token,
			allowCodeAccess: config.GitHub.AllowCodeAccess,
		})
	}

	if config.GitLab != nil {
		instances = append(instances, scmInstance{
			typ:             SCMTypeGitLab,
			baseURL:         config.GitLab.BaseURL,
			token:           config.GitLab.Token,
			allowCodeAccess: config.GitLab.AllowCodeAccess,
		})
	}

	if config.BitBucket != nil {
		instances = append(instances, scmInstance{
			typ:             SCMTypeBitBucket,
			baseURL:         config.BitBucket.BaseURL,
			token:           config.BitBucket.Token,
			allowCodeAccess: config.BitBucket.AllowCodeAccess,
		})
	}

	if config.AzureDevOps != nil {
		instances = append(instances, scmInstance{
			typ:             SCMTypeAzureDevOps,
			baseURL:         config.AzureDevOps.BaseURL,
			token:           config.AzureDevOps.Token,
			allowCodeAccess: config.AzureDevOps.AllowCodeAccess,
		})
	}

	return instances
}

func PopulateAllowLists(config *Config) error {
	for _, scm := range config.Inbound.scmInstances() {
		var (
			allowlist Allowlist
			err       error
		)

		switch scm.typ {
		case SCMTypeGitHub:
			allowlist, err = buildGitHubAllowlist(scm)
		case SCMTypeGitLab:
			allowlist, err = buildGitLabAllowlist(scm)
		case SCMTypeBitBucket:
			allowlist, err = buildBitBucketAllowlist(scm)
		case SCMTypeAzureDevOps:
			allowlist, err = buildAzureDevOpsAllowlist(scm)
		default:
			return fmt.Errorf("unknown scm type %q", scm.typ)
		}

		if err != nil {
			return err
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist, allowlist...)
	}

	return nil
}

func buildGitHubAllowlist(scm scmInstance) (Allowlist, error) {
	var allowlist Allowlist

	gitHubBaseUrl, err := url.Parse(scm.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse github base URL: %v", err)
	}

	// the Semgrep AppSec Platform fetches repository contents using the git smart transfer protocol
	// which requests resources which don't have an api suffix, e.g. /api/v3/
	// see https://git-scm.com/book/be/v2/Git-Internals-Transfer-Protocols
	githubRootUrl, err := url.Parse(gitHubBaseUrl.Scheme + "://" + gitHubBaseUrl.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to build github root URL: %v", err)
	}

	var headers map[string]string
	if scm.token != "" {
		headers = map[string]string{
			"Authorization": fmt.Sprintf("Bearer %v", scm.token),
		}
	} else {
		headers = map[string]string{}
	}

	allowlist = append(allowlist,
		// repo info
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/user").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/user/repos").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get the authenticated user's membership in an organization
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/user/memberships/orgs/:org").String(),
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
		// get PR comment reactions
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/comments/:comment_id/reactions").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// list branches
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/branches").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get branch
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/branches/:branch").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// post issue comment
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/issues/:number/comments").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		// list organizations
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/organizations").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get an organization
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// check app installation for an org
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/installation").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// check repos for an org
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/repos").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// alternative: check repos for an installation
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/installation/repositories").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// check app installation for a personal account
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/users/:user/installation").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// check repo installation for a personal account
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/users/:user/installation/repositories").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// initiate app installation
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app-manifests/:code/conversions").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		// get app installation
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app/installations/:id/access_tokens").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:org/:repo/actions/secrets/SEMGREP_APP_TOKEN").String(),
			Methods:           ParseHttpMethods([]string{"PUT"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:org/:repo/actions/secrets/public-key").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/contents/.github/workflows/semgrep.yml").String(),
			Methods:           ParseHttpMethods([]string{"GET", "PUT"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/installation").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app/hook/config").String(),
			Methods:           ParseHttpMethods([]string{"GET", "PATCH"}),
			SetRequestHeaders: headers,
		},
		// list and get webhook deliveries for the GitHub App
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app/hook/deliveries").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/app/hook/deliveries/:delivery_id").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/check-runs").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/check-runs/:check_run_id").String(),
			Methods:           ParseHttpMethods([]string{"PATCH"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/compare/:basehead").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/:number/comments/:comment_id").String(),
			Methods:           ParseHttpMethods([]string{"PATCH"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/comments/:comment_id").String(),
			Methods:           ParseHttpMethods([]string{"PATCH"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/:number/comments/:comment_id/replies").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/teams").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/teams/:team_slug/members").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/members").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/users/:username").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/hooks").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/hooks/:hook_id").String(),
			Methods:           ParseHttpMethods([]string{"DELETE", "PATCH"}),
			SetRequestHeaders: headers,
		},
		// list and get deliveries for an organization webhook
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/hooks/:hook_id/deliveries").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/orgs/:org/hooks/:hook_id/deliveries/:delivery_id").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/statuses/:commit").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/collaborators/:username/permission").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/refs").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
	)

	if scm.allowCodeAccess {
		allowlist = append(allowlist,
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/contents").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// get contents of file
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/contents/*").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Commits
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/commits").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// discover refs
			AllowlistItem{
				URL:               githubRootUrl.JoinPath("/:owner/:repo/info/refs").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// download repo contents
			AllowlistItem{
				URL:               githubRootUrl.JoinPath("/:owner/:repo/git-upload-pack").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// push repo contents
			AllowlistItem{
				URL:               githubRootUrl.JoinPath("/:owner/:repo/git-receive-pack").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// resolve the base branch SHA before creating the autofix branch.
			// A wildcard, not :ref — ref names span path segments ("heads/main",
			// "heads/feature/DEV-1/fix") and :ref only matches a single one.
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/ref/*").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Code Autofix commits on GitHub through the Git database API, not
			// by pushing over the git transfer protocol. A commit is assembled
			// from separate objects, so the next five entries are one unit:
			// allowlisting a subset fails partway through, mid-commit.
			//
			// read the parent commit for its tree. Not the same endpoint as
			// /repos/:owner/:repo/commits above — that one lists commits, and
			// allowing it does not admit this.
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/commits/:sha").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// upload each changed file
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/blobs").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// build the tree the commit will point at
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/trees").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// create the commit
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/commits").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// move the autofix branch to the new commit. A wildcard for the
			// same reason as git/ref/* above, and the autofix branch itself
			// spans segments ("semgrep-autofix/1787673035").
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/git/refs/*").String(),
				Methods:           ParseHttpMethods([]string{"PATCH"}),
				SetRequestHeaders: headers,
			},
			// create pull request
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
		)
	}

	return appendRepositoryIDRules(allowlist), nil
}

// GitHub answers a request for a renamed or transferred repository with a
// redirect to its id-addressed form, keeping everything after the repository
// segment. These rules are derived from the ones already built so that both
// spellings carry the same methods, headers and allowCodeAccess gating.
func appendRepositoryIDRules(allowlist Allowlist) Allowlist {
	// Only the API rules are redirected this way. The git smart-HTTP rules hang
	// off the host root and have no id-addressed form.
	repoSegments := []string{"/repos/:owner/:repo", "/repos/:org/:repo"}

	byID := make(Allowlist, 0, len(allowlist))
	for _, item := range allowlist {
		for _, segment := range repoSegments {
			if !strings.Contains(item.URL, segment) {
				continue
			}

			// The id is constrained to digits, so these rules admit no segment
			// the name-addressed ones would not.
			mirrored := item
			mirrored.URL = strings.Replace(item.URL, segment, `/repositories/:id(\d+)`, 1)
			byID = append(byID, mirrored)
			break
		}
	}

	return append(allowlist, byID...)
}

func buildGitLabAllowlist(scm scmInstance) (Allowlist, error) {
	var allowlist Allowlist

	gitLabBaseUrl, err := url.Parse(scm.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitlab base URL: %v", err)
	}

	// the Semgrep AppSec Platform fetches repository contents using the git smart transfer protocol
	// which requests resources which don't have an api suffix, e.g. /api/v4/
	// see https://git-scm.com/book/be/v2/Git-Internals-Transfer-Protocols
	gitLabRootUrl, err := url.Parse(gitLabBaseUrl.Scheme + "://" + gitLabBaseUrl.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to build gitlab root URL: %v", err)
	}

	var headers map[string]string
	if scm.token != "" {
		headers = map[string]string{
			"PRIVATE-TOKEN": scm.token,
		}
	} else {
		headers = map[string]string{}
	}

	allowlist = append(allowlist,
		// Group webhooks
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/hooks").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST", "PUT"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/hooks/:hook").String(),
			Methods:           ParseHttpMethods([]string{"DELETE"}),
			SetRequestHeaders: headers,
		},
		// List all members of a group
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/members/all").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Namespace info
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/namespaces/:namespace").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// repo info
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Repo webhooks
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/hooks").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/hooks/:hook").String(),
			Methods:           ParseHttpMethods([]string{"DELETE"}),
			SetRequestHeaders: headers,
		},
		// Get a group member
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/members/all/:user").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Get a repo member
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/members/all/:user").String(),
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
		// Projects
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/:entity_type/:namespace/projects").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// list branches / check existence. Creating a branch (POST) mutates the
		// repo, so it is gated behind allowCodeAccess below.
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/branches").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Get branch
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/branches/:branch").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// post MR comment
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		// post MR comment reply
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
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
		// Get reactions to comments
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note/award_emoji").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Get scm token info
		AllowlistItem{
			URL:               gitLabBaseUrl.JoinPath("/personal_access_tokens/self").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
	)

	if scm.allowCodeAccess {
		allowlist = append(allowlist,
			// get contents of file
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/files/*").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// create the branch the fix commits onto
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/branches").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// Commits (GET to list; POST to create the commit carrying the fix,
			// which is how Code Autofix writes a change on GitLab)
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/commits").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST"}),
				SetRequestHeaders: headers,
			},
			// Compare branches
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/compare").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// get merge base
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/merge_base").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Update commit status
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/statuses/:commit").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// discover refs ({:namespace/}+ requires one or more non-empty namespace
			// segments, so GitLab subgroups of any depth match without admitting
			// double-slash paths). String-concatenated rather than JoinPath'd
			// because url.URL serialization percent-encodes `{` and `}`, which the
			// URL Pattern parser would then reject.
			AllowlistItem{
				URL:               gitLabRootUrl.String() + "/{:namespace/}+:project/info/refs",
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// download project contents
			AllowlistItem{
				URL:               gitLabRootUrl.String() + "/{:namespace/}+:project/git-upload-pack",
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// push project contents
			AllowlistItem{
				URL:               gitLabRootUrl.String() + "/{:namespace/}+:project/git-receive-pack",
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// create merge request
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
		)
	}

	return allowlist, nil
}

func buildBitBucketAllowlist(scm scmInstance) (Allowlist, error) {
	var allowlist Allowlist

	bitBucketBaseUrl, err := url.Parse(scm.baseURL)

	if err != nil {
		return nil, fmt.Errorf("failed to parse bitbucket base URL: %v", err)
	}

	// the Semgrep AppSec Platform fetches repository contents using the git smart transfer protocol
	// which requests resources which don't have the typical `/rest/api/latest/scm/` api suffix
	// see https://git-scm.com/book/be/v2/Git-Internals-Transfer-Protocols
	bitBucketRootUrl, err := url.Parse(bitBucketBaseUrl.Scheme + "://" + bitBucketBaseUrl.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to build bitbucket root URL: %v", err)
	}

	var headers map[string]string
	if scm.token != "" {
		headers = map[string]string{
			"Authorization": fmt.Sprintf("Bearer %v", scm.token),
		}
	} else {
		headers = map[string]string{}
	}

	allowlist = append(allowlist,
		// version information and other application properties
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/application-properties").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// project info
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get repos
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// repo info
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// default branch
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/default-branch").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// list branches / check existence with filterText. Creating a branch
		// (POST) mutates the repo, so it is gated behind allowCodeAccess below.
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/branches").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// pull requests
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// post PR comment
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/comments").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		// get and update PR comment
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/comments/:comment").String(),
			Methods:           ParseHttpMethods([]string{"GET", "PUT"}),
			SetRequestHeaders: headers,
		},
		// post blockerPR comment
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/blocker-comments").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		// repository webhooks
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/webhooks").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/webhooks/:webhook").String(),
			Methods:           ParseHttpMethods([]string{"PUT", "DELETE"}),
			SetRequestHeaders: headers,
		},
		// namespace webhooks
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/webhooks").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               bitBucketBaseUrl.JoinPath("/projects/:project/webhooks/:webhook").String(),
			Methods:           ParseHttpMethods([]string{"PUT", "DELETE"}),
			SetRequestHeaders: headers,
		},
	)

	// Deliberately absent: GET /admin/groups, which the platform's list-teams
	// permission preflight calls. Unlike the equivalent preflights on the other
	// providers, Bitbucket Data Center exposes groups only under /admin, and the
	// point of the broker is a narrow tunnel — a capability check does not justify
	// putting an administrative endpoint in the on-by-default allowlist.

	if scm.allowCodeAccess {
		allowlist = append(allowlist,
			// file contents (GET to read; PUT to write the fix, which is how
			// Bitbucket Data Center's edit-file endpoint commits a change)
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/browse/*").String(),
				Methods:           ParseHttpMethods([]string{"GET", "PUT"}),
				SetRequestHeaders: headers,
			},
			// update commit build status
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/commits/:commit/builds").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// discover refs
			AllowlistItem{
				URL:               bitBucketRootUrl.JoinPath("/scm/:project/:repo/info/refs").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// download repo contents
			AllowlistItem{
				URL:               bitBucketRootUrl.JoinPath("/scm/:project/:repo/git-upload-pack").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// get commits
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/commits").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// create the branch the fix commits onto. Also the endpoint the
			// write-permission preflight POSTs to, so that check now reports
			// "no write access" on a read-only deployment, which is accurate.
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/branches").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// create pull request
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
		)
	}

	return allowlist, nil
}

func buildAzureDevOpsAllowlist(scm scmInstance) (Allowlist, error) {
	var allowlist Allowlist

	azureDevOpsBaseUrl, err := url.Parse(scm.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse azure devops base URL: %v", err)
	}

	vsaexBaseUrl := strings.Replace(scm.baseURL, "dev.azure.com", "vsaex.dev.azure.com", 1)
	vsaexUrl, err := url.Parse(vsaexBaseUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse azure devops vsaex base URL: %v", err)
	}

	var headers map[string]string
	if scm.token != "" {
		headers = map[string]string{
			"Authorization": fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(scm.token))),
		}
	} else {
		headers = map[string]string{}
	}

	allowlist = append(allowlist,
		// Check organization access
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/connectionData").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// Namespace info
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/projects/:project").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get repos
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// repo info
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// refs (GET for branch existence check; POST to create a branch)
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/refs").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		// get pull requests
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get pull request iterations
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// get pull request iteration changes
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations/:iterationId/changes").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
		// post and update PR comment
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads").String(),
			Methods:           ParseHttpMethods([]string{"POST", "PATCH"}),
			SetRequestHeaders: headers,
		},
		// post and update PR comment reply
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments").String(),
			Methods:           ParseHttpMethods([]string{"POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments/:commentId").String(),
			Methods:           ParseHttpMethods([]string{"PATCH"}),
			SetRequestHeaders: headers,
		},
		// namespace webhooks
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/hooks/subscriptions").String(),
			Methods:           ParseHttpMethods([]string{"GET", "POST"}),
			SetRequestHeaders: headers,
		},
		AllowlistItem{
			URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/hooks/subscriptions/:subscriptionId").String(),
			Methods:           ParseHttpMethods([]string{"PUT", "DELETE"}),
			SetRequestHeaders: headers,
		},
		// list teams
		AllowlistItem{
			URL:               vsaexUrl.JoinPath("/:namespace/_apis/groupentitlements").String(),
			Methods:           ParseHttpMethods([]string{"GET"}),
			SetRequestHeaders: headers,
		},
	)

	if scm.allowCodeAccess {
		allowlist = append(allowlist,
			// get file content
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/items").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// update commit status
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/commits/:commit/statuses").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// discover refs
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_git/:repo/info/refs").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// download repo contents
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_git/:repo/git-upload-pack").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// get pull request
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/pullrequests/:number").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// commit the fix. Azure DevOps has no create-commit endpoint: a
			// commit is written as a push, with refUpdates naming the branch,
			// which is why no branch appears in the path.
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pushes").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// create pull request. A separate entry rather than adding POST to
			// the read-only pullRequests entry above, so opening a PR stays
			// gated as it is on the other three providers.
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
		)
	}

	return allowlist, nil
}
