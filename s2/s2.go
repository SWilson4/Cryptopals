package s2

import (
	"crypto/aes"
	"cryptopals/s1"
	"encoding/base64"
	"os"
)

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
