package block

import (
	"crypto/cipher"
)

// This file provides an implementation of the CBC block cipher mode. The organization is similar to that of Go's
// crypto/cipher package for compatibility with Go's AES code, but the implementation is done "from scratch", in the
// spirit of the challenges.

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

type cbcEncrypter cbc

func newCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("CBC mode: IV length is not equal to block size")
	}

	return &cbcEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func (m *cbcEncrypter) BlockSize() int { return m.blockSize }

func (m *cbcEncrypter) CryptBlocks(dst, src []byte) {
	// Note: since this is used only with Go's built-in AES encrypt/decrypt, which checks for incomplete overlap, I'm
	// not going to dive into it here.
	if len(src)%m.blockSize != 0 {
		panic("CBC EncryptBlocks: length of src is not a multiple of block size")
	}

	if len(dst) < len(src) {
		panic("CBC EncryptBlocks: dst and src are of different sizes")
	}

	salt := m.iv
	for i := 0; i < len(src); i += m.blockSize {
		tmp, err := fixedXOR(salt, src[i:i+m.blockSize])
		if err != nil {
			panic("CBC EncryptBlocks: XOR error")
		}
		m.b.Encrypt(dst[i:i+m.blockSize], tmp)
		salt = dst[i : i+m.blockSize]
	}
}

type cbcDecrypter cbc

func newCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("CBC mode: IV length is not equal to block size")
	}

	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func (m *cbcDecrypter) BlockSize() int { return m.blockSize }

func (m *cbcDecrypter) CryptBlocks(dst, src []byte) {
	// Note: since this is used only with Go's built-in AES encrypt/decrypt, which checks for incomplete overlap, I'm
	// not going to dive into it here.
	if len(src)%m.blockSize != 0 {
		panic("CBC DecryptBlocks: length of src is not a multiple of block size")
	}

	if len(dst) < len(src) {
		panic("CBC DecryptBlocks: dst and src are of different sizes")
	}

	salt := m.iv
	tmp := make([]byte, m.blockSize)
	for i := 0; i < len(src); i += m.blockSize {
		m.b.Decrypt(tmp, src[i:i+m.blockSize])
		plaintextBlock, err := fixedXOR(tmp, salt)
		if err != nil {
			panic("CBC DecryptBlocks: XOR error")
		}

		copy(dst[i:i+m.blockSize], plaintextBlock)
		salt = src[i : i+m.blockSize]
	}
}
