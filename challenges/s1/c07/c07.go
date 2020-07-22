package main

import (
	"cryptopals/block"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("c07.in")
	if err != nil {
		log.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("YELLOW SUBMARINE"))
	plaintext, err := block.AESECB(file, key)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", rawPlaintext)
}
