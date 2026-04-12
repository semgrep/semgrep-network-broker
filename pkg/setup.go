package pkg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// BrokerInstance matches the proto BrokerInstance message returned by the API.
type BrokerInstance struct {
	DeploymentId  uint64 `json:"deployment_id"`
	PublicKey     string `json:"public_key"`
	PeerIp        string `json:"peer_ip"`
	AddressOffset int32  `json:"address_offset"`
}

// RegisterBrokerInstanceResponse is the JSON response from the register API.
type RegisterBrokerInstanceResponse struct {
	Config BrokerInstance `json:"config"`
}

// GenerateKeyPair generates a new WireGuard private/public key pair.
// Returns (privateKeyBase64, publicKeyBase64, error).
func GenerateKeyPair() (string, string, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := privateKey.PublicKey()
	privB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	pubB64 := base64.StdEncoding.EncodeToString(publicKey[:])

	return privB64, pubB64, nil
}

// RegisterBrokerInstance registers a WireGuard public key with the Semgrep backend
// and returns the assigned broker instance configuration.
func RegisterBrokerInstance(deploymentId int, publicKey string, appToken string) (*BrokerInstance, error) {
	hostname := getSemgrepHostname()

	apiURL := url.URL{
		Scheme: "https",
		Host:   hostname,
		Path:   fmt.Sprintf("/api/broker/v1/%d/config", deploymentId),
	}

	body := map[string]interface{}{
		"deployment_id": deploymentId,
		"public_key":    publicKey,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", apiURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", appToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to register broker instance: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to register broker instance: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result RegisterBrokerInstanceResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	log.WithField("peer_ip", result.Config.PeerIp).Info("setup.registered")
	return &result.Config, nil
}

// FetchDefaultConfig fetches the default broker config from the Semgrep backend.
// Returns the raw JSON bytes.
func FetchDefaultConfig(deploymentId int) ([]byte, error) {
	hostname := getSemgrepHostname()

	apiURL := url.URL{
		Scheme: "https",
		Host:   hostname,
		Path:   fmt.Sprintf("/api/broker/v1/%d/default-config", deploymentId),
	}

	resp, err := http.DefaultClient.Get(apiURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch default config from %s: %v", hostname, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch default config: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read default config response: %v", err)
	}

	return body, nil
}

// BuildConfigYAML generates a complete broker config YAML file from the default
// config, the generated private key, and the assigned local address.
func BuildConfigYAML(defaultConfigJSON []byte, privateKeyB64 string, localAddress string) ([]byte, error) {
	// Parse the default config to extract wireguard peer info and heartbeat
	var defaultConfig struct {
		Config struct {
			Inbound struct {
				Wireguard struct {
					Peers []struct {
						PublicKey                   string `json:"public_key"`
						Endpoint                    string `json:"endpoint"`
						AllowedIps                  string `json:"allowed_ips"`
						PersistentKeepaliveInterval int    `json:"persistent_keepalive_interval"`
					} `json:"peers"`
					Mtu        int      `json:"mtu"`
					ListenPort int      `json:"listen_port"`
					Dns        []string `json:"dns"`
				} `json:"wireguard"`
				Heartbeat struct {
					URL                       string `json:"url"`
					IntervalSeconds           int    `json:"interval_seconds"`
					TimeoutSeconds            int    `json:"timeout_seconds"`
					PanicAfterFailureCount    int    `json:"panic_after_failure_count"`
					FirstHeartbeatMustSucceed bool   `json:"first_heartbeat_must_succeed"`
				} `json:"heartbeat"`
				Allowlist []struct {
					URL     string   `json:"url"`
					Methods []string `json:"methods"`
				} `json:"allowlist"`
				ProxyListenPort int `json:"proxy_listen_port"`
			} `json:"inbound"`
		} `json:"config"`
	}

	if err := json.Unmarshal(defaultConfigJSON, &defaultConfig); err != nil {
		return nil, fmt.Errorf("failed to parse default config JSON: %v", err)
	}

	inbound := defaultConfig.Config.Inbound

	// Build YAML manually for clean, readable output
	var buf bytes.Buffer
	buf.WriteString("# Semgrep Network Broker Configuration\n")
	buf.WriteString("# Generated by: semgrep-network-broker setup\n")
	buf.WriteString("# Documentation: https://semgrep.dev/docs/semgrep-ci/network-broker\n")
	buf.WriteString("#\n")
	buf.WriteString("# WARNING: Do not share the privateKey value with anyone, including Semgrep.\n")
	buf.WriteString("\n")
	buf.WriteString("inbound:\n")
	buf.WriteString("  wireguard:\n")
	buf.WriteString(fmt.Sprintf("    localAddress: \"%s\"\n", localAddress))
	buf.WriteString(fmt.Sprintf("    privateKey: \"%s\"\n", privateKeyB64))

	if inbound.Wireguard.Mtu > 0 {
		buf.WriteString(fmt.Sprintf("    mtu: %d\n", inbound.Wireguard.Mtu))
	}
	if inbound.Wireguard.ListenPort > 0 {
		buf.WriteString(fmt.Sprintf("    listenPort: %d\n", inbound.Wireguard.ListenPort))
	}
	if len(inbound.Wireguard.Dns) > 0 {
		buf.WriteString("    dns:\n")
		for _, dns := range inbound.Wireguard.Dns {
			buf.WriteString(fmt.Sprintf("      - \"%s\"\n", dns))
		}
	}

	if len(inbound.Wireguard.Peers) > 0 {
		buf.WriteString("    peers:\n")
		for _, peer := range inbound.Wireguard.Peers {
			buf.WriteString(fmt.Sprintf("      - publicKey: \"%s\"\n", peer.PublicKey))
			if peer.Endpoint != "" {
				buf.WriteString(fmt.Sprintf("        endpoint: \"%s\"\n", peer.Endpoint))
			}
			if peer.AllowedIps != "" {
				buf.WriteString(fmt.Sprintf("        allowedIps: \"%s\"\n", peer.AllowedIps))
			}
			if peer.PersistentKeepaliveInterval > 0 {
				buf.WriteString(fmt.Sprintf("        persistentKeepaliveInterval: %d\n", peer.PersistentKeepaliveInterval))
			}
		}
	}

	// Heartbeat
	if inbound.Heartbeat.URL != "" {
		buf.WriteString("\n  heartbeat:\n")
		buf.WriteString(fmt.Sprintf("    url: \"%s\"\n", inbound.Heartbeat.URL))
		if inbound.Heartbeat.IntervalSeconds > 0 {
			buf.WriteString(fmt.Sprintf("    intervalSeconds: %d\n", inbound.Heartbeat.IntervalSeconds))
		}
		if inbound.Heartbeat.TimeoutSeconds > 0 {
			buf.WriteString(fmt.Sprintf("    timeoutSeconds: %d\n", inbound.Heartbeat.TimeoutSeconds))
		}
		if inbound.Heartbeat.FirstHeartbeatMustSucceed {
			buf.WriteString("    firstHeartbeatMustSucceed: true\n")
		}
	}

	// Proxy listen port
	if inbound.ProxyListenPort > 0 {
		buf.WriteString(fmt.Sprintf("\n  proxyListenPort: %d\n", inbound.ProxyListenPort))
	}

	// SCM placeholders
	buf.WriteString("\n  # Uncomment and configure the SCMs you need:\n")
	buf.WriteString("  #\n")
	buf.WriteString("  # github:\n")
	buf.WriteString("  #   baseUrl: https://github.example.com/api/v3\n")
	buf.WriteString("  #   allowCodeAccess: false\n")
	buf.WriteString("  #\n")
	buf.WriteString("  # gitlab:\n")
	buf.WriteString("  #   baseUrl: https://gitlab.example.com/api/v4\n")
	buf.WriteString("  #   allowCodeAccess: false\n")
	buf.WriteString("  #\n")
	buf.WriteString("  # bitbucket:\n")
	buf.WriteString("  #   baseUrl: https://bitbucket.example.com\n")
	buf.WriteString("  #   allowCodeAccess: false\n")
	buf.WriteString("  #\n")
	buf.WriteString("  # azuredevops:\n")
	buf.WriteString("  #   baseUrl: https://dev.azure.com/your-org\n")
	buf.WriteString("  #   allowCodeAccess: false\n")

	return buf.Bytes(), nil
}
