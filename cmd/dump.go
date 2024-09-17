package cmd

import (
	"encoding/json"
	"os"

	"github.com/semgrep/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump current config",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := pkg.LoadConfig(configFiles, deploymentId, brokerIndex)
		if err != nil {
			log.Panic(err)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		if err := enc.Encode(config); err != nil {
			log.Panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(dumpCmd)
}
