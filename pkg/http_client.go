package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

func (hcc *HttpClientConfig) BuildRoundTripper() (http.RoundTripper, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if len(hcc.AdditionalCACerts) > 0 {
		certPool, err := x509.SystemCertPool()
		log.WithField("message", "Adding additional CA Certs").Info("httpClient.config")
		if err != nil {
			return nil, err
		}
		if certPool == nil {
			return nil, fmt.Errorf("failed to get system cert pool. Adding additional CA certs is not possible")
		} else {
			for i := range hcc.AdditionalCACerts {
				caCert, err := os.ReadFile(hcc.AdditionalCACerts[i])
				if err != nil {
					return nil, fmt.Errorf("failed to add CA cert to pool: %v", err)
				}

				if ok := certPool.AppendCertsFromPEM(caCert); !ok {
					return nil, fmt.Errorf("failed to add CA cert to pool: %v", hcc.AdditionalCACerts[i])
				}
			}
		}
		minVersion := uint16(tls.VersionTLS13)
		switch hcc.TlsMinVersion {
		case "1.2":
			minVersion = uint16(tls.VersionTLS12)
		case "1.3":
			minVersion = uint16(tls.VersionTLS13)
		default:
			if hcc.TlsMinVersion != "" {
				return nil, fmt.Errorf("invalid tlsMinVersion: %q. tlsMinVersion must be '1.2' or '1.3' — older TLS versions are not supported", hcc.TlsMinVersion)
			}
		}
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    certPool,
			MinVersion: minVersion,
		}
	}

	return transport, nil
}
