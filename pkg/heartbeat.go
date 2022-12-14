package pkg

import (
	"context"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func (config *HeartbeatConfig) Start(dc func(ctx context.Context, network, addr string) (net.Conn, error)) func() {
	ticker := time.NewTicker(time.Duration(config.IntervalSeconds) * time.Second)
	done := make(chan bool)
	failures := -1

	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: dc,
		},
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}

	execute := func() {
		resp, err := httpClient.Get(config.URL)
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
		} else {
			if failures != 0 {
				log.Info("Established connectivity with r2c")
			}
			log.Debug("Heartbeat OK")
			failures = 0
		}
	}

	execute()
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

	return func() {
		done <- true
	}
}
