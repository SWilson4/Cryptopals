package block

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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

// Returns n random bytes.
func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// Returns an oracle which randomly salts, then encrypts, a plaintext with a random AES key (different each time) in
// either ECB or CBC mode. Also returns true iff ECB mode is used.
func GetAESECBCBCEncryptionOracle() (func([]byte) []byte, bool) {
	ecb := randInt(0, 2)
	return func(plaintext []byte) []byte {
		pre, post := randInt(5, 11), randInt(5, 11)
		prefix, postfix := randBytes(pre), randBytes(post)
		saltedPlaintext := append(prefix, plaintext...)
		saltedPlaintext = append(saltedPlaintext, postfix...)
		p := newPKCS(16)
		paddedPlaintext := p.pad(saltedPlaintext)
		key := randBytes(16)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		var encrypter cipher.BlockMode
		if ecb == 0 {
			encrypter = newECBEncrypter(block)
		} else {
			iv := randBytes(16)
			encrypter = newCBCEncrypter(block, iv)
		}
		ciphertext := make([]byte, len(paddedPlaintext))
		encrypter.CryptBlocks(ciphertext, paddedPlaintext)
		return ciphertext
	}, ecb == 0
}

// Returns true iff the oracle is using ECB mode.
func ECBCBCDetectionOracle(oracle func([]byte) []byte) bool {
	plaintext := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	ciphertext := oracle(plaintext)
	return countRepeats(ciphertext, 16) > 0
}

// Returns an AES-128-ECB encryption oracle that appends a given base64-encoded salt to a plaintext and encrypts with a
// fixed random key.
func GetAESECBEncryptionOracle(salt string) func([]byte) []byte {
	rawSalt, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		panic(err)
	}

	key := randBytes(16)
	return func(plaintext []byte) []byte {
		saltedPlaintext := append(plaintext, rawSalt...)
		p := newPKCS(16)
		paddedPlaintext := p.pad(saltedPlaintext)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		encrypter := newECBEncrypter(block)
		ciphertext := make([]byte, len(paddedPlaintext))
		encrypter.CryptBlocks(ciphertext, paddedPlaintext)
		return ciphertext
	}
}
