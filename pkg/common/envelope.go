package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// ErrKeyMismatch is returned if an envelope's KeyID does not match the given private key
var ErrKeyMismatch = errors.New("Private key does not match the public key used to encrypt this message")

// EnvelopeWriter stores metadata and the cipher-text of some JSON-encoded payload
type EnvelopeWriter struct {
	Device    uint32 `json:"dev"`
	KeyID     string `json:"kid"`
	Metadata  any    `json:"meta"`
	Nonce     B64    `json:"nonce"`
	Encrypted B64    `json:"enc"`
}

// Encrypt a value using the given card's public key
func Encrypt(serial uint32, value any) (_ []byte, err error) {
	token, err := OpenSerial(serial, nil)
	if err != nil {
		return
	}
	defer token.Close()

	// Get the serial of an auto-selected device
	serial, err = token.Serial()
	if err != nil {
		return
	}

	slot, err := token.KeyManagement()
	if err != nil {
		return
	}

	envelope := EnvelopeWriter{Device: serial}
	var secret []byte

	switch key := slot.PublicKey.(type) {
	case *ecdsa.PublicKey:
		envelope.KeyID = FingerprintEC(key)

		Logger.Info("Encrypting with ECDH/AES", zap.String("key_id", envelope.KeyID))
		secret, envelope.Metadata, err = EncryptEC(key)
		if err != nil {
			return
		}
	case *rsa.PublicKey:
		envelope.KeyID = FingerprintRSA(key)

		Logger.Info("Encrypting with RSA+OAEP/AES", zap.String("key_id", envelope.KeyID))
		secret, envelope.Metadata, err = EncryptRSA(key)
		if err != nil {
			return
		}
	}

	block, err := aes.NewCipher(secret)
	if err != nil {
		return
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	data, err := MarshalJSON(value)
	if err != nil {
		return
	}

	envelope.Nonce = make([]byte, aead.NonceSize())
	_, err = rand.Read(envelope.Nonce)
	if err != nil {
		return
	}

	envelope.Encrypted = aead.Seal(nil, envelope.Nonce, data, nil)

	return MarshalJSON(envelope)
}

// EnvelopeReader decodes an envelope message
type EnvelopeReader struct {
	Device    uint32          `json:"dev"`
	KeyID     string          `json:"kid"`
	Metadata  json.RawMessage `json:"meta"`
	Nonce     B64             `json:"nonce"`
	Encrypted B64             `json:"enc"`
}

// Decrypt an object from the given encrypted envelope
func Decrypt(pin string, payload []byte, value any) (err error) {
	var envelope EnvelopeReader

	err = json.Unmarshal(payload, &envelope)
	if err != nil {
		return
	}

	token, err := OpenSerial(envelope.Device, &pin)
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

	switch key := slot.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if kid := FingerprintEC(key); envelope.KeyID != kid {
			return fmt.Errorf("%w: %s != %s", ErrKeyMismatch, envelope.KeyID, kid)
		}

		Logger.Info("Decrypting with ECDH/AES", zap.String("key_id", envelope.KeyID))
		secret, err = DecryptEC(slot, envelope)

	case *rsa.PublicKey:
		// The implementation's RSA private-key doesn't have an exported type
		if kid := FingerprintRSA(key); envelope.KeyID != kid {
			return fmt.Errorf("%w: %s != %s", ErrKeyMismatch, envelope.KeyID, kid)
		}

		Logger.Info("Decrypting with RSA+PKCS1v15/AES", zap.String("key_id", envelope.KeyID))
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
