package block

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"os"
)

// Exported functions take and return only hex- or base64-encoded strings/files. Output encoding is the same as input
// encoding; for example, functions which operate on hex-encoded data will return hex-encoded data.

// Returns the base64 encoding of a given hex-encoded string.
func HexToBase64(hexString string) (string, error) {
	rawBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(rawBytes), nil
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

// Decrypts a base64-encoded file with AES-128 in ECB mode and returns the result as a base64-encoded string.
func AESECB(file *os.File, key string) (string, error) {
	rawCiphertext, err := base64FileToBytes(file)
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

// Decrypts a base64-encoded file with  AES-128 in CBC mode and returns the result as a base64-encoded string.
func AESCBC(file *os.File, key, iv string) (string, error) {
	rawCiphertext, err := base64FileToBytes(file)
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

// Actual is true iff the encryption oracle is using ECB mode, detected is true
// iff ECB mode is detected.
func ECBCBCDetectionOracle() (actual, detected bool) {
	plaintext := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	ciphertext, actual := encryptionOracle(plaintext)
	if countRepeats(ciphertext, 16) > 0 {
		detected = true
	}
	return
}
