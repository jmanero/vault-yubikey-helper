package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// CLI root
	CLI = cobra.Command{Use: "vault-yubikey-helper"}

	// Flags global
	Flags = CLI.PersistentFlags()
)

var (
	// Logger global
	Logger *zap.Logger

	// VaultConfig for client
	VaultConfig api.Config

	// Vault API client
	Vault *api.Client
)

// Yubikey options
var (
	Serial uint32
	Pin    string
)

// Login options
var (
	TokenRole string
	TokenPath string = ".vault-token"
	TokenTTL  time.Duration
)

func init() {
	CLI.AddCommand(&cobra.Command{
		Use:               "init FILE",
		Short:             "Initialize a new vault, encrypt its unseal-key and root token, and write to the specified path",
		PersistentPreRunE: PreRun,
		RunE:              Initialize,
		Args:              cobra.ExactArgs(1),
	})

	CLI.AddCommand(&cobra.Command{
		Use:               "unseal FILE",
		Short:             "Decrypt an unseal-key and use it to unseal a vault instance",
		PersistentPreRunE: PreRun,
		RunE:              Unseal,
		Args:              cobra.ExactArgs(1),
	})

	login := &cobra.Command{
		Use:               "login FILE",
		Short:             "Decrypt a root-token and use it to create a local session-token",
		PersistentPreRunE: PreRun,
		RunE:              Login,
		Args:              cobra.ExactArgs(1),
	}
	CLI.AddCommand(login)

	CLI.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List available PIV devices/slots for init, unseal, and transfer operations",
		RunE:  List,
		Args:  cobra.NoArgs,
	})

	CLI.AddCommand(&cobra.Command{
		Use:   "re-encrypt FROM_FILE TO_FILE",
		Short: "Re-encrypt an existing vault-unseal-key with a new PIV key",
		RunE:  ReEncrypt,
		Args:  cobra.ExactArgs(2),
	})

	// Vault client flags
	Flags.StringVar(&VaultConfig.Address, "vault-endpoint", "http://127.0.0.1:8200", "Vault API endpoint")
	Flags.DurationVar(&VaultConfig.MinRetryWait, "vault-min-retry-wait", 1000*time.Millisecond, "Minimum time to wait before retrying when a 5xx error occurs")
	Flags.DurationVar(&VaultConfig.MaxRetryWait, "vault-max-retry-wait", 1500*time.Millisecond, "Maximum time to wait before retrying when a 5xx error occurs")
	Flags.IntVar(&VaultConfig.MaxRetries, "vault-max-retries", 2, "Maximum number of times to retry when a 5xx error occurs. Set to 0 to disable retrying")
	Flags.DurationVar(&VaultConfig.Timeout, "vault-timeout", time.Minute, "Request timeout")

	// Yubikey flags
	Flags.StringVar(&Pin, "pin", "123456", "PIN required to use the PIV device's private key for decryption")
	Flags.Uint32Var(&Serial, "serial", 0, "Select the PIV device to use for init or re-encrypt operations")

	// Try to use the default ~/.vault-token path
	if home, err := os.UserHomeDir(); err == nil {
		TokenPath = filepath.Join(home, ".vault-token")
	}

	login.PersistentFlags().StringVar(&TokenRole, "token-role", "", "Optional role for acquired tokens")
	login.PersistentFlags().StringVar(&TokenPath, "token-path", TokenPath, "Path to write acquired tokens")
	login.PersistentFlags().DurationVar(&TokenTTL, "token-ttl", time.Hour, "TTL for acquired tokens")
}

func main() {
	switch err := Main().(type) {
	case ExitError:
		// Exit with error's code
		os.Exit(err.ExitCode())
	case error:
		// Exit with a non-zero code
		os.Exit(1)
	}
}

// ExitError provides an ExitCode
type ExitError interface {
	ExitCode() int
}

// Main wrapper ensures that deferred functions are run before exiting
func Main() error {
	Logger = zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(CLI.OutOrStderr()),
		zap.NewAtomicLevel(),
	))
	defer Logger.Sync()

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer done()

	return CLI.ExecuteContext(ctx)
}

// PreRun hook
func PreRun(cmd *cobra.Command, arg []string) (err error) {
	Vault, err = api.NewClient(&VaultConfig)
	return
}

// Initialize a new Vault instance and save it's encrypted secrets to a file
func Initialize(cmd *cobra.Command, args []string) (err error) {
	message, err := Vault.Sys().Init(&api.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	})

	if err != nil {
		return
	}

	encrypted, err := common.Encrypt(Serial, message)
	if err != nil {
		return
	}

	common.Logger.Info("Writing encrypted vault secrets", zap.String("path", args[0]))
	return common.WriteAtomic(args[0], encrypted, 0600)
}

// Unseal a Vault instance from an encrypted secrets file
func Unseal(cmd *cobra.Command, args []string) (err error) {
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

	Logger.Info("Unsealing vault")
	res, err := Vault.Sys().Unseal(message.Keys[0])
	if err != nil {
		return
	}

	dump, err := common.MarshalJSON(res)
	cmd.Println(string(dump))

	return
}

// Login to a Vault instance using an encrypted root-token
func Login(cmd *cobra.Command, args []string) (err error) {
	common.Logger.Info("Reading encrypted vault secrets", zap.String("path", args[0]))
	envelope, err := os.ReadFile(args[0])
	if err != nil {
		return
	}

	var message api.InitResponse
	common.Decrypt(Pin, envelope, &message)

	// use the root token to request a scoped token
	Vault.SetToken(message.RootToken)

	req := api.TokenCreateRequest{
		TTL: TokenTTL.String(),
	}

	var res *api.Secret
	if len(TokenRole) > 0 {
		res, err = Vault.Auth().Token().CreateWithRoleWithContext(cmd.Context(), &req, TokenRole)
	} else {
		res, err = Vault.Auth().Token().CreateOrphanWithContext(cmd.Context(), &req)
	}

	if err != nil {
		return
	}

	Logger.Info("Writing token to file", zap.String("lease_id", res.LeaseID), zap.Int("lease_duration", res.LeaseDuration), zap.String("path", TokenPath))
	common.WriteAtomic(TokenPath, []byte(res.Auth.ClientToken), 0600)

	return
}

// ReEncrypt a secret using a second Yubikey for a peer node in a Vault cluster
func ReEncrypt(cmd *cobra.Command, args []string) (err error) {
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

// List PIV devices/slots
func List(cmd *cobra.Command, args []string) (err error) {
	cards, err := common.ScanCards()

	for i, card := range cards {
		cmd.Printf("%d: %s\n", i, card)
	}

	if err != nil {
		cmd.PrintErrln(err)
	}

	return nil
}
