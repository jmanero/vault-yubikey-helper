package main

import (
	"errors"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:   "unseal FILE",
		Short: "Decrypt an unseal-key and use it to unseal a vault instance",
		RunE:  Unseal,
		Args:  cobra.ExactArgs(1),
	})
}

// ErrSealed is returned by failed unseal operations
var ErrSealed = errors.New("Vault has not been unsealed")

// Unseal a Vault instance from an encrypted secrets file
func Unseal(cmd *cobra.Command, args []string) (err error) {
	vault, err := api.NewClient(&VaultConfig)
	if err != nil {
		return
	}

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

	common.Logger.Info("Unsealing vault")
	res, err := vault.Sys().Unseal(message.Keys[0])
	if err != nil {
		return
	}

	if res.Sealed {
		common.Logger.Warn("Unable to unseal vault", zap.Int("t", res.T), zap.Int("n", res.N))
		return ErrSealed
	}

	common.Logger.Info("Unseal successful", zap.String("version", res.Version), zap.String("cluster", res.ClusterName))
	return
}
