package pkg

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/spf13/viper"
)

func TestTlsMinVersion(t *testing.T) {
	t.Cleanup(viper.Reset)

	config, err := LoadConfig(nil, 0)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name       string
		tlsMin     string
		minVersion uint16
	}{
		{"default", config.Inbound.HttpClient.TlsMinVersion, tls.VersionTLS13},
		{"empty", "", tls.VersionTLS13},
		{"1.2", "1.2", tls.VersionTLS12},
		{"1.3", "1.3", tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hcc := HttpClientConfig{TlsMinVersion: tt.tlsMin}
			rt, err := hcc.BuildRoundTripper()
			if err != nil {
				t.Fatalf("Failed to build round tripper: %v", err)
			}

			got := rt.(*http.Transport).TLSClientConfig.MinVersion
			if got != tt.minVersion {
				t.Errorf("MinVersion = %#x, want %#x", got, tt.minVersion)
			}
		})
	}
}

func TestTlsMinVersionInvalid(t *testing.T) {
	hcc := HttpClientConfig{TlsMinVersion: "1.1"}
	if _, err := hcc.BuildRoundTripper(); err == nil {
		t.Error("Expected error for tlsMinVersion 1.1")
	}
}
