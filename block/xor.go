package block

import (
	"bytes"
	"encoding/base64"
	"errors"
	"index/suffixarray"
	"io/ioutil"
	"math/bits"
	"os"
	"unicode/utf8"
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

// Returns the number of spaces, newlines, and lowercase alphabetical characters in plaintext.
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

// Returns the XOR of a given plaintext against a given repeating key.
func repeatingKeyXOR(plaintext, key []byte) []byte {
	keySize := len(key)
	ciphertext := make([]byte, 0, len(plaintext))
	for i := range plaintext {
		ciphertext = append(ciphertext, plaintext[i]^key[i%keySize])
	}
	return ciphertext
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
