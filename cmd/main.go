package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
)

var (
	// CLI root
	CLI = cobra.Command{Use: "vault-yubikey-helper"}

	// Flags global
	Flags = CLI.PersistentFlags()
)

// VaultConfig for client
var VaultConfig api.Config

// Yubikey options
var (
	Serial uint32
	Pin    string
)

func init() {
	// Vault client flags
	Flags.StringVar(&VaultConfig.Address, "vault-endpoint", "http://127.0.0.1:8200", "Vault API endpoint")
	Flags.DurationVar(&VaultConfig.MinRetryWait, "vault-min-retry-wait", 1000*time.Millisecond, "Minimum time to wait before retrying when a 5xx error occurs")
	Flags.DurationVar(&VaultConfig.MaxRetryWait, "vault-max-retry-wait", 1500*time.Millisecond, "Maximum time to wait before retrying when a 5xx error occurs")
	Flags.IntVar(&VaultConfig.MaxRetries, "vault-max-retries", 2, "Maximum number of times to retry when a 5xx error occurs. Set to 0 to disable retrying")
	Flags.DurationVar(&VaultConfig.Timeout, "vault-timeout", time.Minute, "Request timeout")

	// Yubikey flags
	Flags.StringVar(&Pin, "pin", "123456", "PIN required to use the PIV device's private key for decryption")
	Flags.Uint32Var(&Serial, "serial", 0, "Select the PIV device to use for init or re-encrypt operations")
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
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer done()

	return CLI.ExecuteContext(ctx)
}
