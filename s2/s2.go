package s2

import (
	"crypto/aes"
	"cryptopals/s1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
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

// Decrypts a given ciphertext using a given AES-128 key and IV in CBC mode.
func aesCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// Decrypts a base64-encoded file with  AES-128 in CBC mode and returns the result as a base64-encoded string.
func AESCBC(file *os.File, key, iv string) (string, error) {
	rawCiphertext, err := s1.Base64FileToBytes(file)
	if err != nil {
		return "", err
	}

	rawKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	rawIV, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", err
	}

	rawPlaintext, err := aesCBC(rawCiphertext, rawKey, rawIV)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rawPlaintext), nil
}
