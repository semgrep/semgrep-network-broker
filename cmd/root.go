/*
Copyright © 2022 Tom Petr, r2c <tom@r2c.dev>
*/
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/returntocorp/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/dealancer/validate.v2"
)

var configFiles []string

var buildTime = "no build time"
var version = "no version"
var revision = "no revision"

var rootCmd = &cobra.Command{
	Use:     "semgrep-network-broker",
	Version: fmt.Sprintf("%s (%s at %s)", version, revision, buildTime),
	Short:   "semgrep-network-broker brokers network access to and from the Semgrep backend",
	Run: func(cmd *cobra.Command, args []string) {
		// configure clean shutdown
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		done := make(chan bool, 1)
		go func() {
			<-sigs
			log.Info("Shutting down...")
			done <- true
		}()

		// load and validate configs
		config := &pkg.Config{Outbound: pkg.OutboundProxyConfig{Enabled: true, Listen: ":8080", BaseUrl: "https://semgrep.dev/"}, Inbound: pkg.InboundProxyConfig{Metrics: true}}
		for i := range configFiles {
			viper.SetConfigFile(configFiles[i])
			if err := viper.MergeInConfig(); err != nil {
				log.Panic(fmt.Errorf("failed to read config: %v", err))
			}
		}
		if err := viper.Unmarshal(config); err != nil {
			log.Panic(fmt.Errorf("failed to unmarshal config: %v", err))
		}
		if err := validate.Validate(config); err != nil {
			log.Panic(fmt.Errorf("invalid config: %v", err))
		}

		if !config.Inbound.Enabled && !config.Outbound.Enabled {
			panic("neither inbound nor outbound proxies are enabled")
		}

		if config.Debug {
			log.SetLevel(log.DebugLevel)
		}

		// inbound (r2c --> customer) proxy
		if config.Inbound.Enabled {
			teardown, err := config.Inbound.Start(config.Debug)
			if err != nil {
				log.Panic(err)
			}
			defer teardown()
			config.Inbound.Wireguard.PrintInfo()
		}

		// outbound (customer --> r2c) proxy
		if config.Outbound.Enabled {
			config.Outbound.Start()
			log.Infof("Semgrep API proxy to %s listening on %s", config.Outbound.BaseUrl, config.Outbound.Listen)
		}

		<-done
	},
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
