package main

import (
	"cryptopals/block"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("c10.in")
	if err != nil {
		log.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("YELLOW SUBMARINE"))
	// base64 encoding of 16 bytes of zeros
	iv := "AAAAAAAAAAAAAAAAAAAAAA=="
	plaintext, err := block.AESCBC(file, key, iv)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", rawPlaintext)
}
