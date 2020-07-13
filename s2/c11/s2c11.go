package main

import (
	"cryptopals/s2"
	"fmt"
)

func main() {
	for i := 0; i < 10; i++ {
		actual, detected := s2.ECBCBCDetectionOracle()
		if actual {
			fmt.Println("Encryption oracle is using ECB mode.")
		} else {
			fmt.Println("Encryption oracle is using CBC mode.")
		}
		if detected == actual {
			fmt.Println("Detection oracle correctly detected the mode.")
		} else {
			fmt.Println("Detection oracle did not correctly detect the mode.")
		}
	}
}
