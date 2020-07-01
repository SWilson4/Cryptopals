package main

import (
	"cryptopals/s2"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	input := hex.EncodeToString([]byte("YELLOW SUBMARINE"))
	blockSize := 20
	padded, err := s2.PKCSPadding(input, blockSize)
	if err != nil {
		log.Fatal(err)
	}

	rawPadded, err := hex.DecodeString(padded)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", rawPadded)
}
