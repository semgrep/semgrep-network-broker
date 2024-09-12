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
	Short: "Reads a base64 private key from stdin, outputs the corresponding base64 public key",
	Run: func(cmd *cobra.Command, args []string) {
		keyBase64, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Panic(err)
		}

		keyBytes := make([]byte, defaultKeyCount*device.NoisePrivateKeySize)
		n, err := base64.StdEncoding.Decode(keyBytes, keyBase64)
		if err != nil {
			log.Panic(err)
		}
		if n%device.NoisePrivateKeySize != 0 {
			log.Panicf("invalid byte length: %v", n)
		}

		result := make([]byte, 0, n)

		for i := 0; i < n; i += device.NoisePrivateKeySize {
			privateKey, err := wgtypes.NewKey(keyBytes[i : i+device.NoisePrivateKeySize])
			if err != nil {
				log.Panic(err)
			}
			publicKey := privateKey.PublicKey()
			result = append(result, publicKey[:]...)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(result))
	},
}

func init() {
	rootCmd.AddCommand(pubkeyCmd)
}
