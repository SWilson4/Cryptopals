package main

import (
	"cryptopals/block"
	"fmt"
)

func main() {
	oracle, actual := block.GetAESECBCBCEncryptionOracle()
	detected := block.ECBCBCDetectionOracle(oracle)
	if actual == detected {
		fmt.Println("Detection oracle correctly detected the mode.")
	} else {
		fmt.Println("Detection oracle did not correctly detect the mode.")
	}
}
