package main

import (
	"cryptopals/s1"
	"fmt"
	"log"
)

func main() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	output, err := s1.HexToBase64(input)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}
