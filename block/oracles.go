package block

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"
)

// Generates a random int in the range [lo, hi) using crypto.rand.
func randInt(lo, hi int) int {
	if lo > hi {
		panic("randInt: lo > hi")
	}

	bigRand, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		panic(err)
	}

	return int(bigRand.Int64()) + lo
}

// Fills dst with random bytes using crypto.rand.
func randBytes(dst []byte) {
	_, err := rand.Read(dst)
	if err != nil {
		panic(err)
	}
}

// Encrypts a randomly salted plaintext with a random AES key in either ECB or
// CBC mode. Returns true iff ECB mode is used.
func encryptionOracle(rawPlaintext []byte) ([]byte, bool) {
	pre, post := randInt(5, 11), randInt(5, 11)
	prefix, postfix := make([]byte, pre), make([]byte, post)
	randBytes(prefix)
	randBytes(postfix)
	saltedPlaintext := append(prefix, rawPlaintext...)
	saltedPlaintext = append(saltedPlaintext, postfix...)
	p := newPKCS(16)
	paddedPlaintext := p.pad(saltedPlaintext)
	key := make([]byte, 16)
	randBytes(key)
	var encrypter cipher.BlockMode
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ecb := randInt(0, 2)
	if ecb == 0 {
		encrypter = newECBEncrypter(block)
	} else {
		iv := make([]byte, 16)
		randBytes(iv)
		encrypter = newCBCEncrypter(block, iv)
	}
	ciphertext := make([]byte, len(paddedPlaintext))
	encrypter.CryptBlocks(ciphertext, paddedPlaintext)
	return ciphertext, ecb == 0
}
