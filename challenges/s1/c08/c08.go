package main

import (
	"cryptopals/block"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("c08.in")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := block.DetectAESECB(file)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ciphertext)
}
