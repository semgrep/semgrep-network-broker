package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"gopkg.in/dealancer/validate.v2"
)

func (config *FilteredRelayConfig) Matches(body io.Reader) (bool, error) {
	if config.JSONPath == "" {
		return true, nil
	}

	decoder := json.NewDecoder(body)

	var value = make(map[string]interface{})

	if err := decoder.Decode(&value); err != nil {
		return false, fmt.Errorf("error decoding request body json: %v", err)
	}

	result, err := jsonpath.Get(config.JSONPath, value)

	if err != nil {
		return false, fmt.Errorf("error evaluating jsonpath: %v", err)
	}

	if reflect.TypeOf(result).Kind() != reflect.String {
		return false, fmt.Errorf("JSONPath result is not a string")
	}

	resultStr := result.(string)

	for _, val := range config.Equals {
		if resultStr == val {
			return true, nil
		}
	}
	for _, val := range config.Contains {
		if strings.Contains(resultStr, val) {
			return true, nil
		}
	}
	return false, nil
}

func (config *OutboundProxyConfig) Start() error {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return fmt.Errorf("invalid relay config: %v", err)
	}

	if len(config.Relay) == 0 {
		return nil
	}

	// setup http server
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// setup healthcheck
	r.GET(healthcheckPath, func(c *gin.Context) { c.JSON(http.StatusOK, "OK") })

	// setup metrics
	p := ginprometheus.NewPrometheus("gin")
	p.Use(r)

	// setup http proxy
	r.Any("/relay/:name", func(c *gin.Context) {
		relayName := c.Param("name")

		relayConfig, ok := config.Relay[relayName]

		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("no such relay: %v", relayName)})
			return
		}

		buf := &bytes.Buffer{}
		buf.ReadFrom(c.Request.Body)
		defer c.Request.Body.Close()

		match, err := relayConfig.Matches(bytes.NewReader(buf.Bytes()))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("matching error: %v", err)})
			return
		}

		if !match {
			log.Infof("no match")
			c.JSON(http.StatusOK, gin.H{"result": "no match"})
			return
		}

		destinationUrl, err := url.Parse(relayConfig.DestinationURL) // TODO: precompute this
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("url parser error: %v", err)})
			return
		}

		log.Infof("Proxying request: %s %s", c.Request.Method, destinationUrl)
		proxy := httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.Body = io.NopCloser(buf)
				req.URL = destinationUrl
				req.Host = destinationUrl.Host
			},
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// its showtime!
	go r.Run(fmt.Sprintf(":%v", config.ListenPort))
	log.Infof("Listening on :%v", config.ListenPort)

	return nil
}
