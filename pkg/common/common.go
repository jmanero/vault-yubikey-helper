package common

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger for the utility
var Logger = zap.New(zapcore.NewCore(
	zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
	zapcore.AddSync(os.Stdout),
	zap.NewAtomicLevel(),
))

var randsrc rand.Source

func init() {
	randsrc = rand.NewSource(time.Now().Unix())
}

// FingerprintKey is a helper to generate string identifiers for crypto.PublicKey types
func FingerprintKey(key crypto.PublicKey) string {
	hasher := sha256.New()

	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		hasher.Write(pub.X.Bytes())
		hasher.Write(pub.Y.Bytes())

		return fmt.Sprintf("EC:%s<% x>", pub.Params().Name, hasher.Sum(nil))
	case *rsa.PublicKey:
		hasher.Write(pub.N.Bytes())
		hasher.Write([]byte{byte(pub.E >> 24), byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)})

		return fmt.Sprintf("RSA:%d<% x>", pub.N.BitLen(), hasher.Sum(nil))
	default:
		return fmt.Sprintf("Unsupported Key: %T<%v>", key, key)
	}
}

// MarshalJSON is a helper to pretty-print JSON with the default HTML escaping disabled
func MarshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(value)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// WriteAtomic writes small files through temporary paths
func WriteAtomic(name string, data []byte, mode fs.FileMode) (err error) {
	temp := name + "." + strconv.FormatUint(uint64(randsrc.Int63()), 16)

	err = os.WriteFile(temp, data, mode)
	if err != nil {
		return
	}

	defer os.Remove(temp)
	return os.Rename(temp, name)
}
