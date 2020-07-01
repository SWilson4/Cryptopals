package main

import (
	"cryptopals/s1"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("s1c7.in")
	if err != nil {
		log.Fatal(err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("YELLOW SUBMARINE"))
	plaintext, err := s1.AESECB(file, key)
	if err != nil {
		log.Fatal(err)
	}

	rawPlaintext, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", rawPlaintext)
}
