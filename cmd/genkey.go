package cmd

import (
	"encoding/base64"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var genkeyCmd = &cobra.Command{
	Use:   "genkey",
	Short: "Generates a random private key in base64 and prints it to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Panic(fmt.Errorf("failed to generate private key: %v", err))
		}

		fmt.Println(base64.StdEncoding.EncodeToString(privateKey[:]))
	},
}

func init() {
	rootCmd.AddCommand(genkeyCmd)
}
