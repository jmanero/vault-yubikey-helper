package main

import (
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:   "share FROM_FILE TO_FILE",
		Short: "Re-encrypt an existing vault-unseal-key with a new PIV key",
		RunE:  Share,
		Args:  cobra.ExactArgs(2),
	})
}

// Share re-encrypts a secret using a second Yubikey tpo replace keys or add a peer node to a Vault cluster
func Share(cmd *cobra.Command, args []string) (err error) {
	common.Logger.Info("Reading encrypted vault secrets", zap.String("path", args[0]))
	envelope, err := os.ReadFile(args[0])
	if err != nil {
		return
	}

	var message api.InitResponse
	err = common.Decrypt(Pin, envelope, &message)
	if err != nil {
		return
	}

	// TODO: Exclude source key if serial isn't specified
	envelope, err = common.Encrypt(Serial, message)
	if err != nil {
		return
	}

	common.Logger.Info("Writing encrypted vault secrets", zap.String("path", args[1]))
	return common.WriteAtomic(args[1], envelope, 0600)
}
