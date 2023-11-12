package pki

import (
	"encoding/pem"

	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"pault.ag/go/ykpiv"
)

// CLI for pki subcommands
var CLI = cobra.Command{Use: "pki"}

// CLI flag values
var (
	CertFile string
	Lifespan string
)

func init() {
	flags := CLI.PersistentFlags()
	flags.StringVar(&CertFile, "cert-out", "", "Write certificate to a file instead of STDOUT")
	flags.StringVar(&Lifespan, "lifespan", "1y", "Lifespan for the signed certificate")

	CLI.AddCommand(&cobra.Command{
		Use:   "cert",
		Short: "Export the certificate from a Yubikey's signing slot",
		Args:  cobra.NoArgs,
		RunE:  Cert,
	})
}

// Cert writes the pem-formatted certificate for the signature slot to STDOUT or file
func Cert(cmd *cobra.Command, args []string) (err error) {
	token, err := piv.Open(util.Yubikey.WithSlot(ykpiv.Signature))
	if err != nil {
		return
	}
	defer token.Close()

	slot, err := token.Signature()
	if err != nil {
		return
	}

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: slot.Certificate.Raw,
	}

	if len(CertFile) > 0 {
		common.Logger.Info("Writing certificate to file", zap.String("path", CertFile))
		return common.WriteAtomic(CertFile, pem.EncodeToMemory(&block), 0644)
	}

	return pem.Encode(cmd.OutOrStdout(), &block)
}
