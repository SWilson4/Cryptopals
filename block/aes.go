package block

import (
	"crypto/aes"
)

// Decrypts a given ciphertext using a given AES-128 key in ECB mode.
func aesECB(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := newECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// Decrypts a given ciphertext using a given AES-128 key and IV in CBC mode.
func aesCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := newCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
