package main

import (
	"cryptopals/s1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	input, err := os.Open("s1c04.in")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, key, plaintext, err := s1.DetectSingleByteXOR(input)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := hex.DecodeString(plaintext)
	fmt.Printf("Ciphertext:\n%q\n\nKey: %q\n\nPlaintext:\n%q\n", ciphertext, key, rawPlaintext)
}
