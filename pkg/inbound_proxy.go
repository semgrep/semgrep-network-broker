package pkg

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"gopkg.in/dealancer/validate.v2"
)

const errorResponseHeader = "X-Semgrep-Private-Link-Error"
const proxyResponseHeader = "X-Semgrep-Private-Link"
const wireguardHttpPort = 80

func (config *InboundProxyConfig) Start(verbose bool) (func() error, error) {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return nil, fmt.Errorf("invalid inbound config: %v", err)
	}

	// setup wireguard
	dev, tnet, err := SetupWireguard(&config.Wireguard, verbose)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wireguard: %v", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up wireguard device: %v", err)
	}

	// setup http server
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	if config.Metrics {
		p := ginprometheus.NewPrometheus("gin")
		p.Use(r)
	}

	r.GET("/healthcheck", func(c *gin.Context) { c.JSON(http.StatusOK, "OK") })

	// setup http proxy
	r.Any("/proxy/*destinationUrl", func(c *gin.Context) {
		destinationUrl, err := url.Parse(c.Param("destinationUrl")[1:])
		if err != nil {
			c.Header(errorResponseHeader, "1")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		allowlistMatch, exists := config.Allowlist.FindMatch(c.Request.Method, destinationUrl)
		if !exists {
			c.Header(errorResponseHeader, "1")
			c.JSON(http.StatusForbidden, gin.H{"error": "url is not in allowlist"})
			return
		}

		log.Infof("Proxying request: %s %s", c.Request.Method, destinationUrl)
		proxy := httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL = destinationUrl
				req.Host = destinationUrl.Host
				for headerName, headerValue := range allowlistMatch.SetRequestHeaders {
					req.Header.Set(headerName, headerValue)
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Set(proxyResponseHeader, "1")
				for _, headerToRemove := range allowlistMatch.RemoveResponseHeaders {
					resp.Header.Del(headerToRemove)
				}
				return nil
			},
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// its showtime!
	go func() {
		wireguardListener, err := tnet.ListenTCP(&net.TCPAddr{Port: wireguardHttpPort})
		if err != nil {
			log.Panic(fmt.Errorf("failed to start TCP listener: %v", err))
		}

		err = http.Serve(wireguardListener, r.Handler())
		if err != nil {
			log.Panic(fmt.Errorf("failed to start http server: %v", err))
		}
	}()
	return dev.Down, nil
}
