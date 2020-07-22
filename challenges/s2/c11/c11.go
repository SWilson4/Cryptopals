package main

import (
	"cryptopals/block"
	"fmt"
)

func main() {
	for i := 0; i < 10; i++ {
		actual, detected := block.ECBCBCDetectionOracle()
		if detected == actual {
			fmt.Println("Detection oracle correctly detected the mode.")
		} else {
			fmt.Println("Detection oracle did not correctly detect the mode.")
		}
	}
}
