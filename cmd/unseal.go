package main

import (
	"errors"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/envelope"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:    "unseal FILE",
		Short:  "Decrypt an unseal-key and use it to unseal a vault instance",
		PreRun: util.PinFromEnvironment,
		RunE:   Unseal,
		Args:   cobra.ExactArgs(1),
	})
}

// ErrSealed is returned by failed unseal operations
var ErrSealed = errors.New("Vault has not been unsealed")

// Unseal a Vault instance from an encrypted secrets file
func Unseal(cmd *cobra.Command, args []string) (err error) {
	vault, err := api.NewClient(&util.Vault)
	if err != nil {
		return
	}

	common.Logger.Info("Reading encrypted vault secrets", zap.String("path", args[0]))
	encrypted, err := os.ReadFile(args[0])
	if err != nil {
		return
	}

	var message api.InitResponse
	_, err = envelope.Decrypt(encrypted, &message, util.Yubikey.Pin)
	if err != nil {
		return
	}

	common.Logger.Info("Unsealing vault", zap.String("endpoint", util.Vault.Address))
	status, err := vault.Sys().Unseal(message.Keys[0])
	if err != nil {
		return
	}

	if status.Sealed {
		common.Logger.Warn("Unable to unseal vault", zap.Int("t", status.T), zap.Int("n", status.N), zap.Int("progress", status.Progress))
		return ErrSealed
	}

	common.Logger.Info("Unseal successful", zap.String("version", status.Version), zap.String("cluster", status.ClusterName))
	return
}
