package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var replicaCount int

const defaultReplicaCount = 3
const minReplicaCount = 1
const maxReplicaCount = 16

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generates a random Semgrep Network Broker private key and prints it to stdout.",
	Run: func(cmd *cobra.Command, args []string) {
		if replicaCount < minReplicaCount || replicaCount > maxReplicaCount {
			log.Panic(fmt.Errorf("replica count must be between %v and %v", minReplicaCount, maxReplicaCount))
		}

		encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
		defer encoder.Close()

		for i := 0; i < replicaCount; i++ {
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Panic(fmt.Errorf("failed to generate private key %v: %v", i, err))
			}
			if _, err := encoder.Write(privateKey[:]); err != nil {
				log.Panic(fmt.Errorf("failed to write private key %v: %v", i, err))
			}
		}
	},
}

func init() {
	genkeyCmd.PersistentFlags().IntVarP(&replicaCount, "replica-count", "r", defaultReplicaCount, "Number of broker replicas to support")
	rootCmd.AddCommand(genkeyCmd)
}
