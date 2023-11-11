package envelope

import "encoding/base64"

// B64 marshals and unmarshals a slice of byte as a base64 string
type B64 []byte

// Encoding for B64
var Encoding = base64.RawStdEncoding

// MarshalText encodes the slice into standard base64
func (b B64) MarshalText() (data []byte, _ error) {
	data = make([]byte, Encoding.EncodedLen(len(b)))
	Encoding.Encode(data, b)

	return
}

// UnmarshalText decodes the slice from standard base64
func (b *B64) UnmarshalText(data []byte) (err error) {
	*b = make([]byte, Encoding.DecodedLen(len(data)))
	_, err = Encoding.Decode(*b, data)

	return
}
