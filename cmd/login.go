package main

import (
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var login = cobra.Command{
	Use:   "login FILE",
	Short: "Decrypt a root-token and use it to create a local session-token",
	RunE:  Login,
	Args:  cobra.ExactArgs(1),
}

// Login options
var (
	TokenRole     string
	TokenPolicies []string
	TokenPath     string = ".vault-token"
	TokenTTL      time.Duration
)

func init() {
	// Try to use the default ~/.vault-token path, falling back to $PWD/.vault-token if a home directory can't be resolved
	if home, err := os.UserHomeDir(); err == nil {
		TokenPath = filepath.Join(home, ".vault-token")
	}

	flags := login.PersistentFlags()

	flags.StringVar(&TokenRole, "token-role", "", "Optional role for acquired token")
	flags.StringArrayVar(&TokenPolicies, "token-policy", []string{}, "Optional policies for acquired token")
	flags.StringVar(&TokenPath, "token-path", TokenPath, "Path to write acquired token")
	flags.DurationVar(&TokenTTL, "token-ttl", time.Hour, "TTL for acquired token")

	CLI.AddCommand(&login)
}

// Login to a Vault instance using an encrypted root-token
func Login(cmd *cobra.Command, args []string) (err error) {
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
	common.Decrypt(Pin, envelope, &message)

	// use the root token to request a scoped token
	vault.SetToken(message.RootToken)

	req := api.TokenCreateRequest{
		Policies: TokenPolicies,
		NoParent: true,
		TTL:      TokenTTL.String(),
	}

	var secret *api.Secret
	if len(TokenRole) > 0 {
		common.Logger.Info("Requesting token with role")
		secret, err = vault.Auth().Token().CreateWithRoleWithContext(cmd.Context(), &req, TokenRole)
	} else {
		common.Logger.Info("Requesting orphan token")
		secret, err = vault.Auth().Token().CreateOrphanWithContext(cmd.Context(), &req)
	}

	if err != nil {
		return
	}

	common.Logger.Info("Writing token to file", zap.String("lease_id", secret.LeaseID), zap.Int("lease_duration", secret.LeaseDuration), zap.String("path", TokenPath))
	common.WriteAtomic(TokenPath, []byte(secret.Auth.ClientToken), 0600)

	return
}
