package envelope

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
)

// RSAMetadata stores state required for decryption of a PKCS1v15/AES encrypted payload
type RSAMetadata struct {
	CipherKey B64 `json:"eck"`
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
func DecryptRSA(key crypto.Decrypter, envelope Reader) (secret []byte, err error) {
	var meta RSAMetadata
	err = json.Unmarshal(envelope.Metadata, &meta)
	if err != nil {
		return
	}

	// Decrypt the symmetrical secret
	secret, err = key.Decrypt(rand.Reader, meta.CipherKey, rsa.PKCS1v15DecryptOptions{SessionKeyLen: 32})
	return
}
