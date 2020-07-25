package main

import (
	"cryptopals/block"
	"encoding/base64"
	"fmt"
)

func main() {
	salt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	oracle := block.GetAESECBEncryptionOracle(salt)
	found := block.ByteAtATimeECBDecryption(oracle)
	if salt == found {
		fmt.Println("Successfully found the salt.")
		rawSalt, _ := base64.StdEncoding.DecodeString(found)
		fmt.Printf("Salt: %q\n", rawSalt)
	}
}
