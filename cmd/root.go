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
var debug bool

var rootCmd = &cobra.Command{
	Use:     "semgrep-network-broker",
	Version: fmt.Sprintf("%s (%s at %s)", build.Version, build.Revision, build.BuildTime),
	Short:   "semgrep-network-broker brokers network access to and from the Semgrep backend",
	Run: func(cmd *cobra.Command, args []string) {
		if debug {
			log.SetLevel(log.DebugLevel)
		}

		// setup signal handler for clean shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		doneCh := make(chan bool, 1)
		reloadCh := make(chan bool, 1)
		go func() {
			for {
				sig := <-sigCh
				log.Debugf("Received signal: %v", sig)
				if sig == syscall.SIGHUP {
					reloadCh <- true
				} else {
					close(doneCh)
				}
			}
		}()

		// load config(s)
		config, err := pkg.LoadConfig(configFiles)
		if err != nil {
			log.Panic(err)
		}

		// start the broker
		teardowns, err := StartNetworkBroker(config)
		if err != nil {
			log.Panicf("Failed to start broker: %v", err)
		}

		for {
			select {
			case <-doneCh:
				log.Info("Shutting down...")
				teardowns.Teardown()
				return
			case <-reloadCh:
				newConfig, err := pkg.LoadConfig(configFiles)
				if err != nil {
					log.Errorf("Failed to reload config: %v", err)
					continue
				}

				log.Info("Starting broker with new config...")
				newTeardowns, err := StartNetworkBroker(newConfig)
				if err != nil {
					log.Errorf("Failed to start new broker (old broker remains): %v", err)
					newTeardowns.Teardown()
					continue
				}

				log.Info("Stopping old broker...")
				teardowns.Teardown()

				teardowns = newTeardowns
			}
		}
	},
}

func StartNetworkBroker(config *pkg.Config) (*pkg.TeardownFuncs, error) {
	teardowns := &pkg.TeardownFuncs{}

	// bring up wireguard interface
	tnet, wireguardTeardown, err := config.Inbound.Wireguard.Start()
	teardowns.Push(wireguardTeardown)
	if err != nil {
		return teardowns, fmt.Errorf("failed to start wireguard: %v", err)
	}

	// start periodic heartbeats
	heartbeatTeardown, err := config.Inbound.Heartbeat.Start(tnet, fmt.Sprintf("semgrep-network-broker/%v (rev %v)", build.Version, build.Revision))
	teardowns.Push(heartbeatTeardown)
	if err != nil {
		return teardowns, fmt.Errorf("heartbeat failed: %v", err)
	}

	// start inbound proxy (r2c --> customer)
	inboundTeardown, err := config.Inbound.Start(tnet)
	teardowns.Push(inboundTeardown)
	if err != nil {
		return teardowns, fmt.Errorf("failed to start inbound proxy: %v", err)
	}

	return teardowns, nil
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringArrayVarP(&configFiles, "config", "c", nil, "config file(s)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug logging")
}
