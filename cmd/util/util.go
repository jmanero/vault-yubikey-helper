package util

import (
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"github.com/spf13/cobra"
)

// Global configuration registers shared by subcommand packages
var (
	Vault   api.Config
	Yubikey piv.Options
)

// PinFromEnvironment is a PreRun hook to set the Yubikey PIN for the command from an environment variable
func PinFromEnvironment(cmd *cobra.Command, _ []string) {
	if cmd.Flag("pin").Changed {
		// Use pin explicitly set by the command flag
		return
	}

	if value, has := os.LookupEnv("YUBIKEY_PIN"); has && len(value) > 0 {
		common.Logger.Info("Using yubikey pin from environment variable YUBIKEY_PIN")
		Yubikey.Pin = value
	}
}

// ExitError provides an ExitCode
type ExitError interface {
	ExitCode() int
}
