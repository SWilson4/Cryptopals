package block

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"unicode/utf8"
)

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

// Returns a base64-encoded guess of the (key, plaintext) pair corresponding to a base64-encoded file, assuming that the
// file has been XORed against a repeating key.
func BreakRepeatingKeyXOR(file *os.File) (key, plaintext string, err error) {
	rawCiphertext, err := base64FileToBytes(file)
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

		score := countRepeats(rawLine, 16)
		if score >= maxScore {
			maxScore = score
			ciphertext = line
		}
	}
	return ciphertext, nil
}

// Returns the block size (in bytes) of the cipher used by a given encryption
// oracle (up to 32). If unsuccessful, returns -1.
func findBlockSize(oracle func([]byte) []byte) int {
	plaintext := make([]byte, 0)
	for i := 2; i <= 64; i += 2 {
		plaintext = append(plaintext, '0', '0')
		ciphertext := oracle(plaintext)
		if bytes.Equal(ciphertext[0:i/2], ciphertext[i/2:i]) {
			return i / 2
		}
	}
	return -1
}

// Returns the length of the desired salt.
func findSaltLength(oracle func([]byte) []byte, blockSize int) int {
	in := make([]byte, 0)
	k := 0
	n := len(oracle(in)) / blockSize
	m := n
	for m == n {
		in = append(in, 0)
		k++
		m = len(oracle(in)) / blockSize
	}
	return blockSize*n - k
}

// Given a number of known blocks, returns the next unknown block of the desired salt, up to its length.
func getBlock(oracle func([]byte) []byte, known []byte, blockSize, saltLen int) []byte {
	in := append(make([]byte, blockSize-1), known...)
	block := make([]byte, 0)
	for i := 0; i < blockSize; i++ {
		dummy := make([]byte, blockSize-len(block)-1)
		want := oracle(dummy)
		want = want[len(known) : len(known)+blockSize]
		for b := 0; b < 257; b++ {
			if b == 256 {
				panic("reached 256")
			}
			in = append(in, byte(b))
			out := oracle(in)
			out = out[len(known) : len(known)+blockSize]
			if bytes.Equal(out, want) {
				block = append(block, byte(b))
				if len(known)+len(block) == saltLen {
					return block
				}
				in = in[1:]
				break
			}
			in = in[:len(in)-1]
		}
	}
	return block
}

// Given an AES-128-ECB encryption oracle which encrypts a given string prepended to a fixed string using a fixed key,
// returns the fixed string.
func byteAtATimeECBDecryption(oracle func([]byte) []byte) []byte {
	if !ECBCBCDetectionOracle(oracle) {
		panic("Oracle is not using ECB mode")
	}

	blockSize := findBlockSize(oracle)
	saltLen := findSaltLength(oracle, blockSize)
	salt := make([]byte, 0)
	for len(salt) < saltLen {
		salt = append(salt, getBlock(oracle, salt, blockSize, saltLen)...)
	}
	return salt
}

// Given an AES-128-ECB encryption oracle which encrypts a given string prepended to a fixed string using a fixed key,
// returns the fixed string.
func ByteAtATimeECBDecryption(oracle func([]byte) []byte) string {
	return base64.StdEncoding.EncodeToString(byteAtATimeECBDecryption(oracle))
}
