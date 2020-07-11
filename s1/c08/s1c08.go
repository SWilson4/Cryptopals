package main

import (
	"cryptopals/s1"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("s1c08.in")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := s1.DetectAESECB(file)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(ciphertext)
}
