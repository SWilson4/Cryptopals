package s2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"cryptopals/s1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
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

// Returns hexString padded according to PKCS with a given block size.
func PKCSPadding(hexString string, blockSize uint8) (string, error) {
	rawBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	p := newPKCS(blockSize)
	rawPadded := p.pad(rawBytes)
	return hex.EncodeToString(rawPadded), nil
}

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
		encrypter = s1.NewECBEncrypter(block)
	} else {
		iv := make([]byte, 16)
		randBytes(iv)
		encrypter = NewCBCEncrypter(block, iv)
	}
	ciphertext := make([]byte, len(paddedPlaintext))
	encrypter.CryptBlocks(ciphertext, paddedPlaintext)
	return ciphertext, ecb == 0
}

// Actual is true iff the encryption oracle is using ECB mode, detected is true
// iff ECB mode is detected.
func ECBCBCDetectionOracle() (actual, detected bool) {
	plaintext := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	ciphertext, actual := encryptionOracle(plaintext)
	if s1.CountRepeats(ciphertext, 16) > 0 {
		detected = true
	}
	return
}
