package main

import (
	"cryptopals/s2"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	input := hex.EncodeToString([]byte("YELLOW SUBMARINE"))
	padded, err := s2.PKCSPadding(input, 20)
	if err != nil {
		log.Fatal(err)
	}

	rawPadded, err := hex.DecodeString(padded)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%q\n", rawPadded)
}
