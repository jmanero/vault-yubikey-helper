package piv

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"

	"github.com/jmanero/vault-yubikey-helper/pkg/common"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/term"
	"pault.ag/go/ykpiv"
)

// Errors
var (
	ErrNoCards   = errors.New("No PIV devices detected")
	ErrInvalidID = errors.New("Invalid device identifier")
)

// Options for selecting and opening a Yubikey device
type Options struct {
	Serial        uint32
	Slot          *ykpiv.SlotId
	Pin           string
	ManagementKey []byte
	Avoid         []uint
	Verbose       bool

	exclude map[uint32]struct{}
}

// AskManagementKey creates a password prompt to input a management key without displaying it on terminals
func (opts Options) AskManagementKey() (err error) {
	fmt.Printf("Management Key (Serial %d):  [🔒] ", opts.Serial)
	hkey, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return
	}

	fmt.Println()

	opts.ManagementKey = make([]byte, hex.DecodedLen(len(hkey)))
	_, err = hex.Decode(opts.ManagementKey, hkey)
	return
}

// Copy options into a new instance
func (opts Options) Copy() Options {
	// Copy the Avoid slice
	avoid := make([]uint, len(opts.Avoid))

	copy(avoid, opts.Avoid)
	opts.Avoid = avoid

	// Reset the internal exclude set
	opts.exclude = nil

	return opts
}

// WithSlot returns a copy of the OPtions instance with its Slot parameter set
func (opts Options) WithSlot(slot ykpiv.SlotId) Options {
	out := opts.Copy()
	out.Slot = &slot

	return out
}

// GetPin is a helper to return a pointer to the Option instance's Pin string or nil
func (opts *Options) GetPin() *string {
	if len(opts.Pin) > 0 {
		return &opts.Pin
	}

	return nil
}

// Exclude checks if the given serial is configured to be avoided
func (opts *Options) Exclude(serial uint32) (has bool) {
	if opts.exclude == nil {
		// Make a set from list of serials to avoid
		exclude := make(map[uint32]struct{})
		for _, entry := range opts.Avoid {
			exclude[uint32(entry)] = struct{}{}
		}

		// Reasonably thread-save assignment: assuming the set of Avoid []uint is static, racing threads will achieve the same result
		opts.exclude = exclude
	}

	_, has = opts.exclude[serial]
	return
}

// CardInfo stores information about a PIV device for inspection
type CardInfo struct {
	Name     string
	Version  []byte
	Serial   uint32
	Selected bool

	Slot        string
	PublicKey   crypto.PublicKey
	Certificate *x509.Certificate
}

// TryCard attempts to open and read information from a PIV device
func TryCard(name string, opts Options) (info CardInfo, token *ykpiv.Yubikey, err error) {
	token, err = ykpiv.New(ykpiv.Options{
		Reader:        name,
		PIN:           opts.GetPin(),
		ManagementKey: opts.ManagementKey,
		Verbose:       opts.Verbose,
	})

	if err != nil {
		return
	}

	// Ensure that token is closed if an error is returned
	defer func() {
		if err != nil {
			token.Close()
			token = nil
		}
	}()

	info.Serial, err = token.Serial()
	if err != nil {
		return
	}

	info.Version, err = token.Version()
	if err != nil {
		return
	}

	if opts.Slot != nil {
		var slot *ykpiv.Slot
		info.Slot = opts.Slot.String()

		// Verify that the slot is provisioned and get its public-key and certificate
		slot, err = token.Slot(*opts.Slot)
		if err != nil {
			return
		}

		info.PublicKey = slot.PublicKey
		info.Certificate = slot.Certificate
	}

	return
}

// Open attempts to open a PIV device by its serial number. A value of 0 uses the first suitable device.
func Open(opts Options) (token *ykpiv.Yubikey, err error) {
	devices, err := ykpiv.Readers()
	if err != nil {
		return
	}

	if len(devices) == 0 {
		return nil, ErrNoCards
	}

	var info CardInfo
	var err1 error

	// Scan devices for a matching serial number
	for _, name := range devices {
		info, token, err1 = TryCard(name, opts)
		if err != nil {
			common.Logger.Warn("Unable to open PIV device", zap.Uint32("serial", info.Serial), zap.String("version", string(info.Version)), zap.Error(err1))
			continue
		}

		if opts.Serial > 0 {
			// Only use the specified device if opts.Serial is set
			if info.Serial == opts.Serial {
				common.Logger.Info("Using PIV device with specified serial", zap.Uint32("serial", info.Serial), zap.String("version", string(info.Version)), zap.Bool("pin", opts.GetPin() != nil))
				return
			}

		} else if !opts.Exclude(info.Serial) {
			// Auto-select the first device that isn't avoided
			common.Logger.Info("Using auto-selected PIV device", zap.Uint32("serial", info.Serial), zap.String("version", string(info.Version)), zap.Bool("pin", opts.GetPin() != nil))
			return
		}

		// Close unused token handles
		token.Close()
	}

	// No devices with initialized key-management slots met serial/avoid criteria
	return nil, fmt.Errorf("%w: Unable to use any of the attached PIV devices. Please ensure that a device with the given serial number is attached or provision the KEY_MANAGEMENT slot of at least one attached device to auto-select", ErrNoCards)
}

// Scan attempts to list all available PIV devices and indicate which device would be selected by default
func Scan(opts Options) (cards []CardInfo, selected bool, err error) {
	devices, err := ykpiv.Readers()
	if err != nil {
		return
	}

	for _, name := range devices {
		info, token, err1 := TryCard(name, opts)
		if err1 != nil {
			err = multierr.Append(err, err1)
			continue
		}

		if opts.Serial > 0 {
			// Only use the specified device if opts.Serial is set
			if opts.Serial == info.Serial {
				info.Selected = true
				selected = true
			}

		} else if !opts.Exclude(info.Serial) && !selected {
			// Auto-select the first device that isn't avoided
			info.Selected = true
			selected = true
		}

		cards = append(cards, info)
		token.Close()
	}

	return
}

func (card CardInfo) String() string {
	return fmt.Sprintf("%s\n\tversion: %s\n\tserial:  %d\n\tselected: %t\n\tpubkey:  %v",
		card.Name, string(card.Version), card.Serial, card.Selected, common.FingerprintKey(card.PublicKey))
}
