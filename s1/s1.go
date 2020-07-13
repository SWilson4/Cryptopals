package s1

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"index/suffixarray"
	"io/ioutil"
	"math/bits"
	"os"
	"unicode/utf8"
)

// Exported functions take and return only hex- or base64-encoded strings/files. Output encoding is the same as input
// encoding; for example, functions which operate on hex-encoded data will return hex-encoded data. In functions that
// operate on strings, the variable names "plaintext" and "ciphertext" will refer to strings. In functions that operate
// on bytes, they will refer to byte slices. The name "key" is similar; however, when a key is only one byte long, it
// will be handled as a byte regardless of other function parameter and return types.

// Returns the base64 encoding of a given hex-encoded string.
func HexToBase64(hexString string) (string, error) {
	rawBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rawBytes), nil
}

// Returns the XOR of two byte slices of the same length.
func RawFixedXOR(rawBytes1, rawBytes2 []byte) ([]byte, error) {
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

	rawBytes3, err := RawFixedXOR(rawBytes1, rawBytes2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(rawBytes3), nil
}

// Returns the number of spaces in a given plaintext.
func scorePlaintext(plaintext []byte) int {
	score := 0
	for _, r := range "abcdefghijklmnopqrstuvwxy \n" {
		b := make([]byte, 1)
		utf8.EncodeRune(b, r)
		score += bytes.Count(plaintext, b)
	}
	return score
}

// Returns a guess of the (key, plaintext, plaintext score) tuple corresponding to ciphertext, according to
// scorePlaintext, assuming that ciphertext has been XORed against a single byte.
func breakSingleByteXOR(ciphertext []byte) (byte, []byte, int, error) {
	var maxScore int
	var key byte
	plaintext := make([]byte, 0, len(ciphertext))
	for b := 0; b < 256; b++ {
		var candidate []byte
		for _, c := range ciphertext {
			candidate = append(candidate, byte(b)^c)
		}
		score := scorePlaintext(candidate)
		if score >= maxScore {
			maxScore = score
			key = byte(b)
			plaintext = candidate
		}
	}
	return key, plaintext, maxScore, nil
}

// Returns a guess of the (key, plaintext) pair corresponding to ciphertext, assuming that ciphertext has been XORed
// against a single byte.
func BreakSingleByteXOR(ciphertext string) (byte, string, error) {
	rawCiphertext, err := hex.DecodeString(ciphertext)
	if err != nil {
		return 0, "", err
	}
	key, rawPlaintext, _, err := breakSingleByteXOR(rawCiphertext)
	return key, hex.EncodeToString(rawPlaintext), err
}

// Given a file of hex-encoded data, returns a guess of a (ciphertext, key, plaintext) tuple, assuming that one line of
// the file has been XORed against a single byte.
func DetectSingleByteXOR(file *os.File) (ciphertext string, key byte, plaintext string, err error) {
	scanner := bufio.NewScanner(file)
	var maxScore int
	var rawPlaintext []byte
	for scanner.Scan() {
		line := scanner.Text()
		rawLine, err := hex.DecodeString(line)
		if err != nil {
			return "", 0, "", err
		}
		b, candidate, score, err := breakSingleByteXOR(rawLine)
		if err != nil {
			return "", 0, "", err
		}
		if score >= maxScore {
			maxScore = score
			key = b
			rawPlaintext = candidate
			ciphertext = line
		}
	}
	plaintext = hex.EncodeToString(rawPlaintext)
	return
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

// Returns a guess of the key size, assuming that plaintext has been XORed against a repeating key.
func findKeySize(plaintext []byte) (int, error) {
	normalizedDMin := 8.0
	keySize := 2
	keySizeStart := keySize
	keySizeEnd := 41
	for s := keySizeStart; s < keySizeEnd; s++ {
		if len(plaintext) < 4*s {
			break
		}
		d12, err := hammingDistance(plaintext[:s], plaintext[s:2*s])
		if err != nil {
			return 0, err
		}

		d13, err := hammingDistance(plaintext[:s], plaintext[2*s:3*s])
		if err != nil {
			return 0, err
		}

		d14, err := hammingDistance(plaintext[:s], plaintext[3*s:4*s])
		if err != nil {
			return 0, err
		}

		d23, err := hammingDistance(plaintext[s:2*s], plaintext[2*s:3*s])
		if err != nil {
			return 0, err
		}

		d24, err := hammingDistance(plaintext[s:2*s], plaintext[3*s:4*s])
		if err != nil {
			return 0, err
		}

		d34, err := hammingDistance(plaintext[2*s:3*s], plaintext[3*s:4*s])
		if err != nil {
			return 0, err
		}

		normalizedD := (float64(d12) + float64(d13) + float64(d14) + float64(d23) + float64(d24) + float64(d34)) / (6.0 * float64(s))
		if normalizedD <= normalizedDMin {
			normalizedDMin = normalizedD
			keySize = s
		}
	}
	return keySize, nil
}

func Base64FileToBytes(file *os.File) ([]byte, error) {
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

// Returns a base64-encoded guess of the (key, plaintext) pair corresponding to a base64-encoded file, assuming that the
// file has been XORed against a repeating key.
func BreakRepeatingKeyXOR(file *os.File) (key, plaintext string, err error) {
	rawCiphertext, err := Base64FileToBytes(file)
	if err != nil {
		return
	}

	keySize, err := findKeySize(rawCiphertext)
	if err != nil {
		return
	}

	rawKey := make([]byte, keySize, keySize)
	for i := 0; i < keySize; i++ {
		var block []byte
		for j := i; j < len(rawCiphertext); j += keySize {
			block = append(block, rawCiphertext[j])
		}
		b, _, _, err := breakSingleByteXOR(block)
		if err != nil {
			return "", "", err
		}
		rawKey[i] = b
	}

	rawPlaintext := repeatingKeyXOR(rawCiphertext, rawKey)
	key = base64.StdEncoding.EncodeToString(rawKey)
	plaintext = base64.StdEncoding.EncodeToString(rawPlaintext)
	return
}

// Decrypts a given ciphertext using a given AES-128 key in ECB mode.
func aesECB(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypter := NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// Decrypts a base64-encoded file with AES-128 in ECB mode and returns the result as a base64-encoded string.
func AESECB(file *os.File, key string) (string, error) {
	rawCiphertext, err := Base64FileToBytes(file)
	if err != nil {
		return "", err
	}

	rawKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	rawPlaintext, err := aesECB(rawCiphertext, rawKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rawPlaintext), nil
}

// Counts the number of repeated substrings (counting all occurrences) of length size in rawBytes
func CountRepeats(rawBytes []byte, size int) int {
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

// Given a hex-encoded file, returns a guess of a line which has been encrypted using AES in ECB mode.
func DetectAESECB(file *os.File) (string, error) {
	scanner := bufio.NewScanner(file)
	maxScore := 0
	ciphertext := ""
	for scanner.Scan() {
		line := scanner.Text()
		rawLine, err := hex.DecodeString(line)
		if err != nil {
			return "", err
		}

		score := CountRepeats(rawLine, 16)
		if score >= maxScore {
			maxScore = score
			ciphertext = line
		}
	}
	return ciphertext, nil
}
