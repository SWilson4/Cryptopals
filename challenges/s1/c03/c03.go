package main

import (
	"cryptopals/block"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	ciphertext := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	key, plaintext, err := block.BreakSingleByteXOR(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := hex.DecodeString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Key: %q.\n\nPlaintext: %q\n", key, rawPlaintext)
}
