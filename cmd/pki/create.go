package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"github.com/jmanero/vault-yubikey-helper/pkg/pki"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Flag values
var (
	ManagementKey string

	Template = x509.Certificate{
		BasicConstraintsValid: true,

		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageOCSPSigning,
		},
	}
)

func init() {
	create := cobra.Command{
		Use:   "create",
		Short: "Generate a self-signed certificate for a Yubikey's signing slot",
		RunE:  Create,

		Long: `Generate a self-signed certificate for a Yubikey's signing slot with extensions
not otherwise available in management desktop applications, including setting
the CA flag.

The certificate must be saved back to the respective Yubikey's signing slot
using an external application such as Yubico Authenticator`}

	flags := create.PersistentFlags()
	flags.BoolVar(&Template.IsCA, "ca", false, "Set the certificate's CA flag")
	flags.StringVar(&Template.Subject.CommonName, "cn", "vault-yubikey-helper", "Certificate common-name")

	CLI.AddCommand(&create)
}

// Create the signature slot with a CA certificate
func Create(cmd *cobra.Command, args []string) (err error) {
	token, err := piv.Open(util.Yubikey)
	if err != nil {
		return
	}
	defer token.Close()

	Template.NotBefore, Template.NotAfter = pki.NotBeforeAfter(Lifespan)
	Template.SerialNumber, err = pki.NewSerial()
	if err != nil {
		return
	}

	slot, err := token.Signature()
	if err != nil {
		return
	}

	err = token.Login()
	if err != nil {
		return fmt.Errorf("Failed to authenticate session: %w", err)
	}

	data, err := x509.CreateCertificate(rand.Reader, &Template, &Template, slot.PublicKey, slot)
	if err != nil {
		return
	}

	common.Logger.Info("Signed certificate", zap.Stringer("subject", Template.Subject), zap.Bool("is_ca", Template.IsCA),
		zap.Time("not_before", Template.NotBefore), zap.Time("not_after", Template.NotAfter))

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	}

	if len(CertFile) > 0 {
		common.Logger.Info("Writing certificate to file", zap.String("path", CertFile))
		return common.WriteAtomic(CertFile, pem.EncodeToMemory(&block), 0644)
	}

	return pem.Encode(cmd.OutOrStdout(), &block)
}
