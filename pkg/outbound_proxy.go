package pkg

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/sirupsen/logrus"
	"gopkg.in/dealancer/validate.v2"
)

func (config *OutboundProxyConfig) Start() error {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return fmt.Errorf("invalid outbound config: %v", err)
	}

	go func() {
		baseUrl, err := url.Parse(config.BaseUrl)
		if err != nil {
			log.Panic(err)
		}
		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = baseUrl.Scheme
				req.URL.Host = baseUrl.Host
				if _, ok := req.Header["User-Agent"]; !ok {
					// explicitly disable User-Agent so it's not set to default value
					req.Header.Set("User-Agent", "")
				}
				if config.AppToken != "" {
					req.Header.Set("Authorization", "Bearer "+config.AppToken)
				}
			},
		}

		http.ListenAndServe(config.Listen, proxy)
	}()
	return nil
}
