package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"github.com/jmanero/vault-yubikey-helper/pkg/piv"
	"go.uber.org/zap"
	"pault.ag/go/ykpiv"
)

// Reader decodes an envelope message
type Reader struct {
	Device    uint32          `json:"dev"`
	KeyID     string          `json:"kid"`
	Metadata  json.RawMessage `json:"meta"`
	Nonce     B64             `json:"nonce"`
	Encrypted B64             `json:"enc"`
}

// Decrypt an object from the given encrypted envelope
func Decrypt(payload []byte, value any, pin string) (envelope Reader, err error) {
	err = json.Unmarshal(payload, &envelope)
	if err != nil {
		return
	}

	token, err := piv.Open(piv.Options{Serial: envelope.Device, Slot: &ykpiv.KeyManagement, Pin: pin})
	if err != nil {
		return
	}
	defer token.Close()

	err = token.Login()
	if err != nil {
		return
	}

	slot, err := token.KeyManagement()
	if err != nil {
		return
	}

	var secret []byte

	fingerprint := common.FingerprintKey(slot.PublicKey)
	if envelope.KeyID != fingerprint {
		return envelope, fmt.Errorf("%w: %s != %s", ErrKeyMismatch, envelope.KeyID, fingerprint)
	}

	switch slot.PublicKey.(type) {
	case *ecdsa.PublicKey:
		common.Logger.Info("Decrypting with ECDH/AES", zap.String("key_id", envelope.KeyID))
		secret, err = DecryptEC(slot, envelope)

	case *rsa.PublicKey:
		common.Logger.Info("Decrypting with RSA+PKCS1v15/AES", zap.String("key_id", envelope.KeyID))
		secret, err = DecryptRSA(slot, envelope)
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}

	aead, err := cipher.NewGCMWithNonceSize(block, len(envelope.Nonce))
	if err != nil {
		return
	}

	data, err := aead.Open(nil, envelope.Nonce, envelope.Encrypted, nil)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, value)
	return
}
