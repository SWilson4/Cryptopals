package main

import (
	"cryptopals/block"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	plaintext := hex.EncodeToString([]byte(
		"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))
	key := hex.EncodeToString([]byte("ICE"))
	ciphertext, err := block.RepeatingKeyXOR(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ciphertext)
}
