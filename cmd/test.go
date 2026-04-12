package cmd

import (
	"fmt"
	"os"

	"github.com/semgrep/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test broker connectivity to Semgrep and configured SCMs",
	Long: `Establishes the WireGuard tunnel and verifies that the broker can reach
the Semgrep heartbeat endpoint and each configured source code manager.

A non-zero exit code indicates one or more targets are unreachable.
An HTTP 401/403 response is still considered a PASS (proves network path works).`,
	Run: func(cmd *cobra.Command, args []string) {
		if jsonLog {
			log.SetFormatter(&log.JSONFormatter{FieldMap: log.FieldMap{log.FieldKeyMsg: "event"}})
		}

		config, err := pkg.LoadConfig(configFiles, deploymentId)
		if err != nil {
			log.Panic(err)
		}

		fmt.Println("Starting connectivity test...")
		fmt.Printf("WireGuard local address: %s\n", config.Inbound.Wireguard.LocalAddress)

		results, err := pkg.TestConnectivity(config)
		if err != nil {
			log.Panic(fmt.Errorf("connectivity test failed to start: %v", err))
		}

		pkg.PrintTestResults(results)

		if len(results) == 0 {
			fmt.Println("\nNo targets configured to test. Add SCM configs (github, gitlab, etc.) to your config file.")
			os.Exit(1)
		}

		if !pkg.AllPassed(results) {
			fmt.Println("\nSome connectivity tests failed. Check your network configuration and firewall rules.")
			os.Exit(1)
		}

		fmt.Println("\nAll connectivity tests passed.")
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
