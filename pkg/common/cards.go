package common

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"strconv"

	"go.uber.org/multierr"
	"go.uber.org/zap"
	"pault.ag/go/ykpiv"
)

// Errors
var (
	ErrNoCards   = errors.New("No PIV devices detected")
	ErrInvalidID = errors.New("Invalid device identifier")
)

// CardInfo stores information about a PIV device for inspection
type CardInfo struct {
	Name    string
	Version string
	Serial  string
	Default bool
	PubKey  string
}

// OpenSerial attempts to open a PIV device by its serial number. A value of 0 uses the first suitable device.
func OpenSerial(require uint32, pin *string, avoid ...uint32) (token *ykpiv.Yubikey, err error) {
	devices, err := ykpiv.Readers()
	if err != nil {
		return
	}

	if len(devices) == 0 {
		return nil, ErrNoCards
	}

	// Make a set from list of serials to avoid
	exclude := make(map[uint32]struct{})
	for _, entry := range avoid {
		exclude[entry] = struct{}{}
	}

	// Scan devices for a matching serial number
	for _, name := range devices {
		var err1 error
		token, err1 = ykpiv.New(ykpiv.Options{Reader: name, PIN: pin})
		if err1 != nil {
			Logger.Warn("Unable to open token", zap.String("token", name), zap.Error(err))
			continue
		}

		serial, err1 := token.Serial()
		if err1 != nil {
			token.Close()
			Logger.Warn("Unable to read token serial", zap.String("token", name), zap.Error(err))
			continue
		}

		// Select device by serial number, if given
		if require > 0 && require != serial {
			token.Close()
			continue
		} else if _, match := exclude[serial]; match {
			// Exclude specified devices
			token.Close()
			continue
		}

		// Verify that the key-management slot is provisioned
		_, err1 = token.KeyManagement()
		if err1 != nil {
			token.Close()
			continue
		}

		// Use the first key that meets require/exclude parameters and
		Logger.Info("Using PIV device", zap.Uint32("serial", serial), zap.Bool("pin", pin != nil))
		return
	}

	return nil, fmt.Errorf("%w: Unable to use any of the attached PIV devices. Please ensure that a device with the given serial number is attached or provision the KEY_MANAGEMENT slot of at least one attached device to auto-select", ErrNoCards)
}

// ScanCards attempts to list all available PIV devices and indicate which device would be selected by default
func ScanCards() (cards []CardInfo, err error) {
	devices, err := ykpiv.Readers()
	if err != nil {
		return
	}

	var first bool

	for i, name := range devices {
		token, err1 := ykpiv.New(ykpiv.Options{Reader: name})
		if err1 != nil {
			err = multierr.Append(err, err1)
			continue
		}

		serial, err1 := token.Serial()
		if err1 != nil {
			err = multierr.Append(err, err1)
			token.Close()
			continue
		}

		version, err1 := token.Version()
		if err1 != nil {
			err = multierr.Append(err, err1)
			token.Close()
			continue
		}

		cards = append(cards, CardInfo{
			Name:    name,
			Version: string(version),
			Serial:  strconv.FormatUint(uint64(serial), 10),
		})

		slot, err1 := token.KeyManagement()
		if err1 != nil {
			err = multierr.Append(err, err1)
			token.Close()
			continue
		}

		switch key := slot.PublicKey.(type) {
		case *ecdsa.PublicKey:
			cards[i].PubKey = FingerprintEC(key)
		case *rsa.PublicKey:
			cards[i].PubKey = FingerprintRSA(key)
		}

		// Mark the first device with a key-management-key as the default
		cards[i].Default = !first
		first = true

		token.Close()
	}

	return
}

func (card CardInfo) String() string {
	return fmt.Sprintf("%s\n\tversion: %s\n\tserial:  %s\n\tdefault: %t\n\tpubkey:  %v",
		card.Name, card.Version, card.Serial, card.Default, card.PubKey)
}
