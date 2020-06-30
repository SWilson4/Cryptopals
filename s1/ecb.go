package s1

import (
	"crypto/cipher"
)

// This file provides an implementation of ECB mode decryption which is similar to Go's implementation of CBC mode.
// https://golang.org/src/crypto/cipher/cbc.go

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode { return (*ecbDecrypter)(newECB(b)) }

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("s1/ecb: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("s1/ecb: output smaller than input")
	}
	/* Not testing overlap here because I can't use the internal package
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("s1/ecb: invalid buffer overlap")
	} */
	if len(src) == 0 {
		return
	}

	start := 0
	end := start + x.blockSize
	for start < len(src) {
		x.b.Decrypt(dst[start:end], src[start:end])

		start, end = end, end+x.blockSize
	}
}
