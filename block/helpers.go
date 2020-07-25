package block

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"index/suffixarray"
	"io/ioutil"
	"math/bits"
	"os"
)

// Returns the base64 encoding of a given hex-encoded string.
func HexToBase64(hexString string) (string, error) {
	rawBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rawBytes), nil
}

// Returns the Hamming distance between two bytes.
func singleByteHammingDistance(b1, b2 byte) int {
	return bits.OnesCount8(b1 ^ b2)
}

// Returns the hamming distance between two byte slices of equal length.
func hammingDistance(rawBytes1, rawBytes2 []byte) (int, error) {
	if len(rawBytes1) != len(rawBytes2) {
		return 0, errors.New("hammingDistance: inputs must be of the same length")
	}

	var d int
	for i := range rawBytes1 {
		d += singleByteHammingDistance(rawBytes1[i], rawBytes2[i])
	}
	return d, nil
}

// Decodes the contents of a base64-encoded file into a byte slice.
func base64FileToBytes(file *os.File) ([]byte, error) {
	base64Text, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	rawBytes := make([]byte, base64.StdEncoding.DecodedLen(len(base64Text)))
	bytesRead, err := base64.StdEncoding.Decode(rawBytes, base64Text)
	if err != nil {
		return nil, err
	}

	return rawBytes[:bytesRead], nil
}

// Counts the number of repeated substrings (counting all occurrences) of length size in rawBytes
func countRepeats(rawBytes []byte, size int) int {
	count := 0
	sa := suffixarray.New(rawBytes)
	m := make(map[int]bool)
	for i := 0; i < len(rawBytes)-size; i++ {
		if m[i] {
			continue
		}
		indices := sa.Lookup(rawBytes[i:i+size], -1)
		for _, j := range indices {
			m[j] = true
		}
		count += len(indices) - 1
	}
	return count
}
