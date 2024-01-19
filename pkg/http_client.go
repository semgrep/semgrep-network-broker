package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
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
		if err != nil {
			return nil, err
		}

		for i := range hcc.AdditionalCACerts {
			caCert, err := os.ReadFile(hcc.AdditionalCACerts[i])
			if err != nil {
				return nil, fmt.Errorf("failed to add CA cert to pool: %v", err)
			}

			if ok := certPool.AppendCertsFromPEM(caCert); !ok {
				return nil, fmt.Errorf("failed to add CA cert to pool: %v", hcc.AdditionalCACerts[i])
			}
		}
		transport.TLSClientConfig = &tls.Config{
			ClientCAs:  certPool,
			MinVersion: tls.VersionTLS13,
		}
	}

	return transport, nil
}
