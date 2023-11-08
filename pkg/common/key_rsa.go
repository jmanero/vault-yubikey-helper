package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// RSAMetadata stores state required for decryption of a PKCS1v15/AES encrypted payload
type RSAMetadata struct {
	CipherKey B64 `json:"eck"`
}

// FingerprintRSA is a helper to generate a human-readable identifier for an RSA public key
func FingerprintRSA(pub *rsa.PublicKey) string {
	hasher := sha256.New()
	hasher.Write(pub.N.Bytes())
	hasher.Write([]byte{byte(pub.E >> 24), byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)})

	return fmt.Sprintf("RSA:%d<% x>", pub.N.BitLen(), hasher.Sum(nil))
}

// EncryptRSA generates and encrypts a shared secret
func EncryptRSA(pub *rsa.PublicKey) (secret []byte, meta RSAMetadata, err error) {
	secret = make([]byte, 32)
	_, err = rand.Read(secret)
	if err != nil {
		return
	}

	// Use the RSA key to encrypt the symmetrical encryption secret
	meta.CipherKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, secret)
	return
}

// DecryptRSA decrypts a shared secret from envelope metadata
func DecryptRSA(key crypto.Decrypter, envelope EnvelopeReader) (secret []byte, err error) {
	var meta RSAMetadata
	err = json.Unmarshal(envelope.Metadata, &meta)
	if err != nil {
		return
	}

	// Decrypt the symmetrical secret
	secret, err = key.Decrypt(rand.Reader, meta.CipherKey, rsa.PKCS1v15DecryptOptions{SessionKeyLen: 32})
	return
}
