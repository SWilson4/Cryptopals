package s2

import (
	"encoding/hex"
	"errors"
)

// Pads rawBytes to have length divisible by blockSize by appending bytes whose value is the number of bytes required.
// If the length of rawBytes is divisible by blockSize, blockSize bytes are appended. Consequently, blockSize must be
// less than 256.
func pkcsPadding(rawBytes []byte, blockSize int) ([]byte, error) {
	toAdd := blockSize - (len(rawBytes) % blockSize)
	if blockSize > 255 {
		return nil, errors.New("PKCS7Padding: block size is too large")
	}
	for i := 0; i < toAdd; i++ {
		rawBytes = append(rawBytes, byte(toAdd))
	}
	return rawBytes, nil
}

// Returns hexString padded according to PKCS with a given block size.
func PKCSPadding(hexString string, blockSize int) (string, error) {
	rawBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	rawPadded, err := pkcsPadding(rawBytes, blockSize)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(rawPadded), nil
}
