package pkg

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gopkg.in/dealancer/validate.v2"
)

const errorResponseHeader = "X-Semgrep-Private-Link-Error"
const proxyResponseHeader = "X-Semgrep-Private-Link"
const healthcheckPath = "/healthcheck"
const destinationUrlParam = "destinationUrl"
const proxyPath = "/proxy/*" + destinationUrlParam

func (config *InboundProxyConfig) Start(tnet *netstack.Net) error {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return fmt.Errorf("invalid inbound config: %v", err)
	}

	// build http transport (needed for custom CA certs, etc...)
	transport, err := config.HttpClient.BuildRoundTripper()
	if err != nil {
		return err
	}

	// setup http server
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// we want this proxy to be transparent, so don't un-escape characters in the URL
	r.UseRawPath = true
	r.UnescapePathValues = false

	r.Use(LoggerWithConfig(log.StandardLogger(), config.Logging.SkipPaths), gin.Recovery())

	// setup healthcheck
	r.GET(healthcheckPath, func(c *gin.Context) { c.JSON(http.StatusOK, "OK") })
	log.WithField("path", healthcheckPath).Info("healthcheck.configured")

	// setup metrics
	p := ginprometheus.NewPrometheus("gin")
	p.Use(r)
	log.WithField("path", p.MetricsPath).Info("metrics.configured")

	// setup http proxy
	r.Any(proxyPath, func(c *gin.Context) {
		logger := log.WithFields(GetRequestFields(c))
		destinationUrl, err := url.Parse(c.Param(destinationUrlParam)[1:])

		// we have to explicitly copy over the query params
		destinationUrl.RawQuery = c.Request.URL.RawQuery

		logger = logger.WithField("destinationUrl", destinationUrl)

		if err != nil {
			logger.WithError(err).Warn("proxy.destination_url_parse")
			c.Header(errorResponseHeader, "1")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		allowlistMatch, exists := config.Allowlist.FindMatch(c.Request.Method, destinationUrl)
		if !exists {
			logger.Warn("allowlist.reject")
			c.Header(errorResponseHeader, "1")
			c.JSON(http.StatusForbidden, gin.H{"error": "url is not in allowlist"})
			return
		}

		logger = logger.WithField("allowlist_match", allowlistMatch.URL)

		reqLogger := logger
		if config.Logging.LogRequestBody || allowlistMatch.LogRequestBody {
			reqBody := &bytes.Buffer{}
			reqBody.ReadFrom(c.Request.Body)
			defer c.Request.Body.Close()
			c.Request.Body = io.NopCloser(reqBody)
			reqLogger = reqLogger.WithField("request_body", reqBody.String())
		}

		if config.Logging.LogRequestHeaders || allowlistMatch.LogRequestHeaders {
			reqLogger = reqLogger.WithField("request_headers", c.Request.Header)
		}

		reqLogger.Info("proxy.request")

		proxy := httputil.ReverseProxy{
			Transport: transport,
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
				respLogger := logger
				if config.Logging.LogResponseBody || allowlistMatch.LogResponseBody {
					respBuf := &bytes.Buffer{}
					respBuf.ReadFrom(resp.Body)
					defer resp.Body.Close()
					resp.Body = io.NopCloser(respBuf)
					respLogger = logger.WithField("response_body", respBuf.String())
				}
				if config.Logging.LogResponseHeaders || allowlistMatch.LogResponseHeaders {
					respLogger = respLogger.WithField("response_headers", resp.Header)
				}
				respLogger.Info("proxy.response")
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

	log.Info("broker.start")

	return nil
}
