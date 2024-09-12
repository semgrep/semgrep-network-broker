package cmd

import (
	"encoding/base64"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var keyCount int

const defaultKeyCount = 3

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generates a random private key in base64 and prints it to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		if keyCount < 1 {
			log.Panic("--key-count must be greater than zero")
		}

		result := make([]byte, 0, device.NoisePrivateKeySize*keyCount)

		for i := 0; i < keyCount; i++ {
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				log.Panic(fmt.Errorf("failed to generate private key: %v", err))
			}
			result = append(result[:], privateKey[:]...)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(result))
	},
}

func init() {
	genkeyCmd.PersistentFlags().IntVarP(&keyCount, "key-count", "k", defaultKeyCount, "Number of keys to generate")
	rootCmd.AddCommand(genkeyCmd)
}
