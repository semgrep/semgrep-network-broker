package pkg

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func (config *HeartbeatConfig) Start(tnet *netstack.Net, userAgent string) (TeardownFunc, error) {
	ticker := time.NewTicker(time.Duration(config.IntervalSeconds) * time.Second)
	done := make(chan bool, 1)
	failures := -1

	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}

	execute := func() bool {
		req, err := http.NewRequest("GET", config.URL, nil)
		if err != nil {
			log.Panic(fmt.Errorf("invalid heartbeat request: %v", err))
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			failures++
			if config.PanicAfterFailureCount > 0 && failures >= config.PanicAfterFailureCount {
				log.Panicf("Heartbeat failed %v times in a row", failures)
			}
			if err != nil {
				log.Warnf("Heartbeat failure: %v", err)
			} else {
				log.Warnf("Heartbeat failure: HTTP %v from %v", resp.StatusCode, config.URL)
			}
			return false
		} else {
			if failures != 0 {
				log.Info("Established connectivity with r2c")
			}
			log.Debug("Heartbeat OK")
			failures = 0
			return true
		}
	}

	success := execute()
	if config.FirstHeartbeatMustSucceed && !success {
		return nil, fmt.Errorf("first heartbeat did not succeed")
	}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				execute()
			}
		}
	}()

	return func() error {
		close(done)
		return nil
	}, nil
}
