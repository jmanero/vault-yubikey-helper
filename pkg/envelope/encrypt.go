package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"go.uber.org/zap"
	"pault.ag/go/ykpiv"
)

// ErrKeyMismatch is returned if an envelope's KeyID does not match the given private key
var ErrKeyMismatch = errors.New("Private key does not match the public key used to encrypt this message")

// Writer stores metadata and the cipher-text of some JSON-encoded payload
type Writer struct {
	Device    uint32 `json:"dev"`
	KeyID     string `json:"kid"`
	Metadata  any    `json:"meta"`
	Nonce     B64    `json:"nonce"`
	Encrypted B64    `json:"enc"`
}

// Encrypt a value using the given card's public key
func Encrypt(value any, opts piv.Options) (_ []byte, err error) {
	token, err := piv.Open(opts.WithSlot(ykpiv.KeyManagement))
	if err != nil {
		return
	}
	defer token.Close()

	// Get the serial of an auto-selected device
	serial, err := token.Serial()
	if err != nil {
		return
	}

	slot, err := token.KeyManagement()
	if err != nil {
		return
	}

	envelope := Writer{Device: serial}
	var secret []byte
	envelope.KeyID = common.FingerprintKey(slot.PublicKey)

	switch key := slot.PublicKey.(type) {
	case *ecdsa.PublicKey:
		common.Logger.Info("Encrypting with ECDH/AES", zap.String("key_id", envelope.KeyID))
		secret, envelope.Metadata, err = EncryptEC(key)

	case *rsa.PublicKey:
		common.Logger.Info("Encrypting with RSA+OAEP/AES", zap.String("key_id", envelope.KeyID))
		secret, envelope.Metadata, err = EncryptRSA(key)
	}

	if err != nil {
		return
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	data, err := common.MarshalJSON(value)
	if err != nil {
		return
	}

	envelope.Nonce = make([]byte, aead.NonceSize())
	_, err = rand.Read(envelope.Nonce)
	if err != nil {
		return
	}

	envelope.Encrypted = aead.Seal(nil, envelope.Nonce, data, nil)

	return common.MarshalJSON(envelope)
}
