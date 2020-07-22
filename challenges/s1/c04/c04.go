package main

import (
	"cryptopals/block"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	input, err := os.Open("c04.in")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, key, plaintext, err := block.DetectSingleByteXOR(input)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := hex.DecodeString(plaintext)
	fmt.Printf("Ciphertext:\n%q\n\nKey: %q\n\nPlaintext:\n%q\n", ciphertext, key, rawPlaintext)
}
