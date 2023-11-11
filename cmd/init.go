package main

import (
	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/envelope"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:   "init FILE",
		Short: "Initialize a new vault, encrypt its unseal-key and root token, and write encrypted message to the specified file",
		RunE:  Initialize,
		Args:  cobra.ExactArgs(1),
	})
}

// Initialize a new Vault instance and save it's encrypted secrets to a file
func Initialize(cmd *cobra.Command, args []string) (err error) {
	vault, err := api.NewClient(&util.Vault)
	if err != nil {
		return
	}

	common.Logger.Info("Initializing vault with 1-of-1 secret", zap.String("endpoint", util.Vault.Address))
	message, err := vault.Sys().Init(&api.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	})

	if err != nil {
		return
	}

	encrypted, err := envelope.Encrypt(message, util.Yubikey)
	if err != nil {
		return
	}

	common.Logger.Info("Writing encrypted vault secrets", zap.String("path", args[0]))
	return common.WriteAtomic(args[0], encrypted, 0600)
}
