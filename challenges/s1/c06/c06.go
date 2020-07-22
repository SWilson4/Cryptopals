package main

import (
	"cryptopals/block"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("c06.in")
	if err != nil {
		log.Fatal(err)
	}

	key, plaintext, err := block.BreakRepeatingKeyXOR(file)
	if err != nil {
		log.Fatal(err)
	}

	rawKey, err := base64.StdEncoding.DecodeString(key)

	rawPlaintext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Key: %q\n\nPlaintext:\n%q\n", rawKey, rawPlaintext)
}
