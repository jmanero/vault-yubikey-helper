package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jmanero/vault-yubikey-helper/cmd/util"
	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"github.com/jmanero/vault-yubikey-helper/pkg/pki"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"pault.ag/go/ykpiv"
)

// CLI flag values
var (
	CSRFile  string
	Lifespan time.Duration
)

func init() {

	sign := cobra.Command{
		Use:    "sign",
		Short:  "Sign a PEM-encoded CSR with a Yubikey's signing slot",
		PreRun: util.PinFromEnvironment,
		RunE:   Sign,
	}

	flags := sign.PersistentFlags()
	flags.StringVar(&CSRFile, "req-in", "", "Read the signing request from a file instead of STDIN")
	flags.DurationVar(&Lifespan, "lifespan", time.Hour*24*365, "Lifespan for the signed certificate")

	CLI.AddCommand(&sign)
}

// Sign a CSR with a Yubikey's signing slot
func Sign(cmd *cobra.Command, args []string) (err error) {
	var data []byte
	if len(CSRFile) > 0 {
		common.Logger.Info("Reading request from file", zap.String("path", CSRFile))
		data, err = os.ReadFile(CSRFile)
	} else {
		data, err = io.ReadAll(cmd.InOrStdin())
	}

	if err != nil {
		return
	}

	req, err := pki.ReadCertificateRequest(data)
	if err != nil {
		return
	}

	template := x509.Certificate{
		Subject: req.Subject,

		ExtraExtensions:       req.Extensions,
		BasicConstraintsValid: true,
	}

	template.NotBefore, template.NotAfter = pki.NotBeforeAfter(Lifespan)
	template.SerialNumber, err = pki.NewSerial()
	if err != nil {
		return
	}

	token, err := piv.Open(util.Yubikey.WithSlot(ykpiv.Signature))
	if err != nil {
		return
	}
	defer token.Close()

	slot, err := token.Signature()
	if err != nil {
		return
	}

	err = token.Login()
	if err != nil {
		return fmt.Errorf("Unable to authenticate session: %w", err)
	}

	data, err = x509.CreateCertificate(rand.Reader, &template, slot.Certificate, req.PublicKey, slot)
	if err != nil {
		return fmt.Errorf("Unable to sign certificate: %w", err)
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
