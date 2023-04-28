/*
Copyright © 2022 Tom Petr, r2c <tom@r2c.dev>
*/
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/returntocorp/semgrep-network-broker/build"
	"github.com/returntocorp/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var configFiles []string

var rootCmd = &cobra.Command{
	Use:     "semgrep-network-broker",
	Version: fmt.Sprintf("%s (%s at %s)", build.Version, build.Revision, build.BuildTime),
	Short:   "semgrep-network-broker brokers network access to and from the Semgrep backend",
	Run: func(cmd *cobra.Command, args []string) {
		// setup signal handler for clean shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		doneCh := make(chan bool, 1)
		go func() {
			<-sigCh
			log.Info("Shutting down...")
			doneCh <- true
		}()

		// load config(s)
		config, err := pkg.LoadConfig(configFiles)
		if err != nil {
			log.Panic(err)
		}

		if config.Inbound == nil && config.Outbound == nil {
			log.Panic("need inbound and/or outbound config")
		}

		// start the broker
		if config.Inbound != nil {
			teardown, err := StartNetworkBroker(config.Inbound)
			if err != nil {
				log.Panic(fmt.Errorf("failed to start broker: %v", err))
			}
			defer teardown()
		}

		// start the relay
		if config.Outbound != nil {
			// start outbound proxy (customer --> r2c)
			if err := config.Outbound.Start(); err != nil {
				log.Panic(fmt.Errorf("failed to start outbound proxy: %v", err))
			}
		}

		// wait for shutdown
		<-doneCh
	},
}

func StartNetworkBroker(config *pkg.InboundProxyConfig) (func() error, error) {
	// bring up wireguard interface
	tnet, wireguardTeardown, err := config.Wireguard.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start wireguard: %v", err)
	}

	// start periodic heartbeats
	heartbeatTeardown, err := config.Heartbeat.Start(tnet, fmt.Sprintf("semgrep-network-broker/%v (rev %v)", build.Version, build.Revision))
	if err != nil {
		wireguardTeardown()
		return nil, fmt.Errorf("heartbeat failed: %v", err)
	}

	teardown := func() error {
		heartbeatTeardown()
		return wireguardTeardown()
	}

	// start inbound proxy (r2c --> customer)
	if err := config.Start(tnet); err != nil {
		teardown()
		return nil, fmt.Errorf("failed to start inbound proxy: %v", err)
	}

	return teardown, nil
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringArrayVarP(&configFiles, "config", "c", nil, "config file(s)")
}
