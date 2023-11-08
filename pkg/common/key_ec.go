package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// ECMetadata stores state required for decryption of an ECDH/AES encrypted payload
type ECMetadata struct {
	EphemeralKey B64 `json:"epk"`
}

// FingerprintEC is a helper to generate a human-readable identifier for an ECDSA public key
func FingerprintEC(key *ecdsa.PublicKey) string {
	hasher := sha256.New()
	hasher.Write(key.X.Bytes())
	hasher.Write(key.Y.Bytes())

	return fmt.Sprintf("EC:%s<% x>", key.Params().Name, hasher.Sum(nil))
}

// EncryptEC derives a DH secret from the given public-ke and an ephemeral private key
func EncryptEC(key *ecdsa.PublicKey) (secret []byte, meta ECMetadata, err error) {
	// Generate an ephemeral private key using the same curve as the PIV key
	ephemeral, err := ecdsa.GenerateKey(key.Curve, rand.Reader)
	if err != nil {
		return
	}

	// Get DH-safe curves from ECDSA keys
	dpub, err := key.ECDH()
	if err != nil {
		return
	}

	dephem, err := ephemeral.ECDH()
	if err != nil {
		return
	}

	// Store the ephemeral public key to re-generate the shared secret for decryption
	meta.EphemeralKey = dephem.PublicKey().Bytes()

	// Derive a shared secret for encipherment
	secret, err = dephem.ECDH(dpub)
	return
}

// DecryptEC re-derives a DH secret from a Yubikey and an ephemeral public-key stored in an envelope's metadata
func DecryptEC(key crypto.Decrypter, envelope EnvelopeReader) (secret []byte, err error) {
	var meta ECMetadata
	err = json.Unmarshal(envelope.Metadata, &meta)
	if err != nil {
		return
	}

	// Recover the shared secret for deciphering
	secret, err = key.Decrypt(nil, meta.EphemeralKey, nil)
	return
}
