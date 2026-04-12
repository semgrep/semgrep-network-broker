package pkg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Both should be valid base64
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Errorf("private key is not valid base64: %v", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Errorf("public key is not valid base64: %v", err)
	}

	// WireGuard keys are 32 bytes
	if len(privBytes) != 32 {
		t.Errorf("private key length: got %d, want 32", len(privBytes))
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key length: got %d, want 32", len(pubBytes))
	}

	// Keys should be different
	if priv == pub {
		t.Error("private and public keys should be different")
	}

	// Two calls should produce different keys
	priv2, pub2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("second GenerateKeyPair failed: %v", err)
	}
	if priv == priv2 {
		t.Error("consecutive calls produced the same private key")
	}
	if pub == pub2 {
		t.Error("consecutive calls produced the same public key")
	}
}

func TestRegisterBrokerInstance(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/broker/v1/123/config") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
		}

		// Parse request body
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to parse request body: %v", err)
		}
		if body["public_key"] != "test-pub-key" {
			t.Errorf("unexpected public_key: %v", body["public_key"])
		}

		// Return response
		resp := RegisterBrokerInstanceResponse{
			Config: BrokerInstance{
				DeploymentId:  123,
				PublicKey:     "test-pub-key",
				PeerIp:        "fdf0:59dc:33cf:9be8:0000:007b:0000:0001",
				AddressOffset: 0,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Override hostname to use test server
	// The function uses getSemgrepHostname() which reads SEMGREP_HOSTNAME env var
	t.Setenv(SemgrepHostnameEnvVar, server.Listener.Addr().String())

	// We need to use the test server's TLS client
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()

	instance, err := RegisterBrokerInstance(123, "test-pub-key", "test-token")
	if err != nil {
		t.Fatalf("RegisterBrokerInstance failed: %v", err)
	}

	if instance.PeerIp != "fdf0:59dc:33cf:9be8:0000:007b:0000:0001" {
		t.Errorf("unexpected peer_ip: %s", instance.PeerIp)
	}
	if instance.PublicKey != "test-pub-key" {
		t.Errorf("unexpected public_key: %s", instance.PublicKey)
	}
}

func TestRegisterBrokerInstance_Error(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "access denied")
	}))
	defer server.Close()

	t.Setenv(SemgrepHostnameEnvVar, server.Listener.Addr().String())
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()

	_, err := RegisterBrokerInstance(123, "test-pub-key", "bad-token")
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestFetchDefaultConfig(t *testing.T) {
	expectedConfig := `{"config":{"inbound":{"wireguard":{"peers":[{"public_key":"abc123"}]}}}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/api/broker/v1/456/default-config") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, expectedConfig)
	}))
	defer server.Close()

	t.Setenv(SemgrepHostnameEnvVar, server.Listener.Addr().String())
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()

	body, err := FetchDefaultConfig(456)
	if err != nil {
		t.Fatalf("FetchDefaultConfig failed: %v", err)
	}

	if string(body) != expectedConfig {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestBuildConfigYAML(t *testing.T) {
	defaultConfigJSON := `{
		"config": {
			"inbound": {
				"wireguard": {
					"peers": [{
						"public_key": "serverPubKey123",
						"endpoint": "wireguard.semgrep.dev:51820",
						"allowed_ips": "::/0",
						"persistent_keepalive_interval": 20
					}],
					"mtu": 1320
				},
				"heartbeat": {
					"url": "https://semgrep.dev/api/broker/heartbeat",
					"interval_seconds": 60,
					"timeout_seconds": 5
				},
				"proxy_listen_port": 80
			}
		}
	}`

	yaml, err := BuildConfigYAML([]byte(defaultConfigJSON), "privateKey123==", "fdf0:59dc:33cf:9be8::1")
	if err != nil {
		t.Fatalf("BuildConfigYAML failed: %v", err)
	}

	output := string(yaml)

	// Check key fields are present
	checks := []string{
		`localAddress: "fdf0:59dc:33cf:9be8::1"`,
		`privateKey: "privateKey123=="`,
		`publicKey: "serverPubKey123"`,
		`endpoint: "wireguard.semgrep.dev:51820"`,
		`allowedIps: "::/0"`,
		`persistentKeepaliveInterval: 20`,
		`mtu: 1320`,
		`url: "https://semgrep.dev/api/broker/heartbeat"`,
		`intervalSeconds: 60`,
		`timeoutSeconds: 5`,
		`proxyListenPort: 80`,
		"WARNING: Do not share the privateKey",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing expected string: %q", check)
		}
	}

	// Check SCM placeholder comments are present
	scmChecks := []string{
		"# github:",
		"# gitlab:",
		"# bitbucket:",
		"# azuredevops:",
	}
	for _, check := range scmChecks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing SCM placeholder: %q", check)
		}
	}
}

func TestBuildConfigYAML_InvalidJSON(t *testing.T) {
	_, err := BuildConfigYAML([]byte("not json"), "key", "addr")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildConfigYAML_EmptyConfig(t *testing.T) {
	yaml, err := BuildConfigYAML([]byte(`{"config":{"inbound":{"wireguard":{}}}}`), "key==", "::1")
	if err != nil {
		t.Fatalf("BuildConfigYAML failed: %v", err)
	}

	output := string(yaml)
	if !strings.Contains(output, `privateKey: "key=="`) {
		t.Error("output missing privateKey")
	}
	if !strings.Contains(output, `localAddress: "::1"`) {
		t.Error("output missing localAddress")
	}
	// Should not contain peers section when empty
	if strings.Contains(output, "peers:") {
		t.Error("output should not contain peers section when no peers configured")
	}
}
