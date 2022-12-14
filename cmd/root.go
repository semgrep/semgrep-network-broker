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

		// load config(s)
		config, err := pkg.LoadConfig(configFiles)
		if err != nil {
			log.Panic(err)
		}

		// start inbound proxy (r2c --> customer)
		teardown, err := config.Inbound.Start()
		if err != nil {
			log.Panic(fmt.Errorf("failed to start inbound proxy: %v", err))
		}
		defer teardown()

		// wait for termination
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
