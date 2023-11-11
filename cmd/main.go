package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jmanero/vault-yubikey-helper/cmd/pki"
	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/spf13/cobra"
)

// CLI root
var CLI = cobra.Command{Use: "vault-yubikey-helper"}

func init() {
	// Register sub-commands
	CLI.AddCommand(&pki.CLI)

	flags := CLI.PersistentFlags()

	// Vault client flags
	flags.StringVar(&util.Vault.Address, "vault-endpoint", "http://127.0.0.1:8200", "Vault API endpoint")
	flags.DurationVar(&util.Vault.MinRetryWait, "vault-min-retry-wait", 1000*time.Millisecond, "Minimum time to wait before retrying when a 5xx error occurs")
	flags.DurationVar(&util.Vault.MaxRetryWait, "vault-max-retry-wait", 1500*time.Millisecond, "Maximum time to wait before retrying when a 5xx error occurs")
	flags.IntVar(&util.Vault.MaxRetries, "vault-max-retries", 2, "Maximum number of times to retry when a 5xx error occurs. Set to 0 to disable retrying")
	flags.DurationVar(&util.Vault.Timeout, "vault-timeout", time.Minute, "Request timeout")

	// Yubikey flags
	flags.StringVar(&util.Yubikey.Pin, "pin", "123456", "PIN required to use the PIV device's private key for decryption. Set environment variable YUBIKEY_PIN to avoid reveling in logs")
	flags.Uint32Var(&util.Yubikey.Serial, "serial", 0, "Select the PIV device to use for init or re-encrypt operations by its serial number")
	flags.UintSliceVar(&util.Yubikey.Avoid, "avoid-serial", []uint{}, "Exclude PIV devices from auto-selection by their serial numbers")
	flags.BoolVar(&util.Yubikey.Verbose, "verbose", false, "Enable verbose logging from the PIV library")
}

func main() {
	switch err := Main().(type) {
	case util.ExitError:
		// Exit with error's code
		os.Exit(err.ExitCode())
	case error:
		// Exit with a non-zero code
		os.Exit(1)
	}
}

// Main wrapper ensures that deferred functions are run before exiting
func Main() error {
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer done()

	return CLI.ExecuteContext(ctx)
}
