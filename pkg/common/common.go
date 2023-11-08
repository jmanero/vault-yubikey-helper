package common

import (
	"bytes"
	"encoding/json"
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
