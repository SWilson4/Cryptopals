package main

import (
	"cryptopals/s1"
	"fmt"
	"log"
)

func main() {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	output, err := s1.FixedXOR(input1, input2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}
