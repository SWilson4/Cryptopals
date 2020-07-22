# Cryptopals
These are my solutions to the [Cryptopals crypto challenges](https://cryptopals.com), in Go. I'll be adding to this repo as I work through the problem sets.

The structure of this repo mimics the structure of the challenges website: each set has a devoted subdirectory, which itself contains a Go file with common code for the challenges in the set and a subdirectory for each challenge in the set. Each challenge subdirectory contains a Go file with a `main` function which solves that particular challenge.

## Table of Contents

I.  [Basics](https://github.com/SWilson4/cryptopals/tree/master/challenges/s1)
    1.  [Convert hex to base64](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c01/c01.go)
    2.  [Fixed XOR](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c02/c02.go)
    3.  [Single-byte XOR cipher](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c03/c03.go)
    4.  [Detect single-character XOR](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c04/c04.go)
    5.  [Implement repeating-key XOR](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c05/c05.go)
    6.  [Break repeating-key XOR](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c06/c06.go)
    7.  [AES in ECB mode](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c07/c07.go)
    8.  [Detect AES in ECB mode](https://github.com/SWilson4/cryptopals/blob/master/challenges/s1/c08/c08.go)
II.  [Block crypto](https://github.com/SWilson4/cryptopals/tree/master/challenges/s2)

    9.  [Implement PKCS#7 padding](https://github.com/SWilson4/cryptopals/blob/master/challenges/s2/c09/c09.go)
    10.  [Implement CBC mode](https://github.com/SWilson4/cryptopals/blob/master/challenges/s2/c10/c10.go)
    11. [An ECB/CBC detection oracle](https://github.com/SWilson4/cryptopals/blob/master/challenges/s2/c11/c11.go)
