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
const healthcheckPath = "/healthcheck"
const destinationUrlParam = "destinationUrl"
const proxyPath = "/proxy/*" + destinationUrlParam

func (config *InboundProxyConfig) Start() (func() error, error) {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return nil, fmt.Errorf("invalid inbound config: %v", err)
	}

	// setup wireguard
	dev, tnet, err := SetupWireguard(&config.Wireguard)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wireguard: %v", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("failed to bring up wireguard device: %v", err)
	}

	log.Info("Wireguard interface is UP:")
	log.Infof("  Local Address: %v", config.Wireguard.LocalAddress)
	for i := range config.Wireguard.Peers {
		log.Infof("  Peer: %+v", config.Wireguard.Peers[i])
	}

	// setup http server
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: config.Logging.SkipPaths,
	}), gin.Recovery())

	// setup healthcheck
	r.GET(healthcheckPath, func(c *gin.Context) { c.JSON(http.StatusOK, "OK") })

	// setup metrics
	p := ginprometheus.NewPrometheus("gin")
	p.Use(r)

	// setup http proxy
	r.Any(proxyPath, func(c *gin.Context) {
		destinationUrl, err := url.Parse(c.Param(destinationUrlParam)[1:])
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
		wireguardListener, err := tnet.ListenTCP(&net.TCPAddr{Port: config.ProxyListenPort})
		if err != nil {
			log.Panic(fmt.Errorf("failed to start TCP listener: %v", err))
		}

		err = r.RunListener(wireguardListener)
		if err != nil {
			log.Panic(fmt.Errorf("failed to start http server: %v", err))
		}
	}()

	heartbeatTeardown := config.Heartbeat.Start(tnet.DialContext)

	return func() error {
		heartbeatTeardown()
		return dev.Down()
	}, nil
}
