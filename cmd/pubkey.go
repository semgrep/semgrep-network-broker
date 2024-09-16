package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Reads a Semgrep Network Broker private key from stdin and ptints the corresponding public key to stdout.",
	Run: func(cmd *cobra.Command, args []string) {

		decoder := base64.NewDecoder(base64.StdEncoding, os.Stdin)
		encoder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
		defer encoder.Close()

		privateKeyBytes := make([]byte, device.NoisePrivateKeySize)

		for i := 0; ; i++ {
			_, err := io.ReadFull(decoder, privateKeyBytes)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Panic(fmt.Errorf("error reading private key %v: %v", i, err))
				}
			}
			privateKey, err := wgtypes.NewKey(privateKeyBytes)
			if err != nil {
				log.Panic(fmt.Errorf("error creating private key %v: %v", i, err))
			}

			publicKey := privateKey.PublicKey()
			if _, err := encoder.Write(publicKey[:]); err != nil {
				log.Panic(fmt.Errorf("error writing public key %v: %v", i, err))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(pubkeyCmd)
}
