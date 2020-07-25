package block

import (
	"encoding/hex"
	"errors"
)

// Returns the XOR of two byte slices of the same length.
func fixedXOR(rawBytes1, rawBytes2 []byte) ([]byte, error) {
	if len(rawBytes1) != len(rawBytes2) {
		return nil, errors.New("Inputs are of different lengths")
	}

	rawBytes3 := make([]byte, len(rawBytes1), len(rawBytes1))
	for i := range rawBytes1 {
		rawBytes3[i] = rawBytes1[i] ^ rawBytes2[i]
	}

	return rawBytes3, nil
}

// Returns the hex-encoded XOR of two given hex-encoded strings of the same length.
func FixedXOR(hexString1, hexString2 string) (string, error) {
	rawBytes1, err := hex.DecodeString(hexString1)
	if err != nil {
		return "", err
	}

	rawBytes2, err := hex.DecodeString(hexString2)
	if err != nil {
		return "", err
	}

	rawBytes3, err := fixedXOR(rawBytes1, rawBytes2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(rawBytes3), nil
}

// Returns the XOR of a given plaintext against a given repeating key.
func repeatingKeyXOR(plaintext, key []byte) []byte {
	keySize := len(key)
	ciphertext := make([]byte, 0, len(plaintext))
	for i := range plaintext {
		ciphertext = append(ciphertext, plaintext[i]^key[i%keySize])
	}
	return ciphertext
}

// Returns the hex-encoding of a given hex-encoded plaintext XORed against a given repeating hex-encoded key.
func RepeatingKeyXOR(plaintext, key string) (string, error) {
	rawPlaintext, err := hex.DecodeString(plaintext)
	if err != nil {
		return "", err
	}

	rawKey, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(repeatingKeyXOR(rawPlaintext, rawKey)), nil
}
