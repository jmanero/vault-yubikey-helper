package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"pault.ag/go/ykpiv"
)

// Errors
var (
	ErrNoPEMObject = errors.New("Unable to decode a PEM object")
)

// MaxSerial is the upper limit for randomly generated certificate serials
var MaxSerial = big.NewInt(math.MaxInt64)

func init() {
	// Fill with 128 bits of 1
	MaxSerial.Mul(MaxSerial, MaxSerial)
}

// NewSerial generates a new random serial bigint
func NewSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, MaxSerial)
}

// NotBeforeAfter generates a pair of time.Time, for NotBefore and NotAfter
// certificate values. NotBefore is the current time, rounded to the previous hour
func NotBeforeAfter(lifetime time.Duration) (time.Time, time.Time) {
	// Round down to the nearest hour
	now := time.Now().UTC()
	rounded := now.Round(time.Hour)
	if rounded.After(now) {
		// Don't round up into the future
		rounded.Add(-time.Hour)
	}

	return rounded, rounded.Add(lifetime)
}

// ReadCertificateRequest attempts to parse a PEM encoded CERTIFICATE REQUEST object
func ReadCertificateRequest(data []byte) (req *x509.CertificateRequest, err error) {
	var block *pem.Block
	for len(data) > 0 {
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%w `CERTIFICATE REQUEST`", ErrNoPEMObject)
		}

		if block.Type == "CERTIFICATE REQUEST" {
			break
		}
	}

	req, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return
	}

	err = req.CheckSignature()
	return
}

// SaveCertificate is copied from the ykpiv library. It removes an intermediary
// x509.Certificate object from the method signature, instead consuming a DER
// encoded certificate directly.
func SaveCertificate(token *ykpiv.Yubikey, slot ykpiv.SlotId, cert []byte) (err error) {
	var message []byte

	values := []asn1.RawValue{
		{Tag: 0x10, IsCompound: true, Class: 0x01, Bytes: cert},
		{Tag: 0x11, IsCompound: true, Class: 0x01, Bytes: []byte{0x00}},
		{Tag: 0x1E, IsCompound: true, Class: 0x03, Bytes: []byte{}},
	}

	for _, value := range values {
		entry, err := asn1.Marshal(value)
		if err != nil {
			return err
		}

		message = append(message, entry...)
	}

	err = token.Login()
	if err != nil {
		return fmt.Errorf("Failed to authenticate session [SaveCertificate]: %w", err)
	}

	return token.SaveObject(slot.Certificate, message)
}
