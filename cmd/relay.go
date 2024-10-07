package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/semgrep/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Reads a base64 private key from stdin, outputs the corresponding base64 public key",
	Run: func(cmd *cobra.Command, args []string) {
		if jsonLog {
			log.SetFormatter(&log.JSONFormatter{FieldMap: log.FieldMap{log.FieldKeyMsg: "event"}})
		}

		// setup signal handler for clean shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		doneCh := make(chan bool, 1)
		go func() {
			sig := <-sigCh
			log.WithField("signal", sig).Info("relay.shutdown")
			doneCh <- true
		}()

		// load config(s)
		config, err := pkg.LoadConfig(configFiles, 0)
		if err != nil {
			log.Panic(err)
		}

		// start the relay
		if err := config.Outbound.Start(); err != nil {
			log.Panic(fmt.Errorf("failed to start relay: %v", err))
		}

		// wait for shutdown
		<-doneCh
	},
}

func init() {
	rootCmd.AddCommand(relayCmd)
}
