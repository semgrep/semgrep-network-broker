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

		keyBytes := make([]byte, device.NoisePrivateKeySize)
		n, err := base64.StdEncoding.Decode(keyBytes, keyBase64)
		if err != nil {
			log.Panic(err)
		}
		if n != device.NoisePrivateKeySize {
			log.Panic(fmt.Sprintf("expected private key to be %d bytes decoded, got %d", device.NoisePrivateKeySize, n))
		}

		privateKey, err := wgtypes.NewKey(keyBytes)
		if err != nil {
			log.Panic(err)
		}

		publicKey := privateKey.PublicKey()

		fmt.Println(base64.StdEncoding.EncodeToString(publicKey[:]))
	},
}

func init() {
	rootCmd.AddCommand(pubkeyCmd)
}
