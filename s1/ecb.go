package s1

import "crypto/cipher"

// This file provides an implementation of the ECB block cipher mode. The organization is similar to that of Go's
// crypto/cipher package for compatibility with Go's AES code, but the implementation is done "from scratch", in the
// spirit of the challenges.

type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (m *ecbEncrypter) BlockSize() int { return m.blockSize }

func (m *ecbEncrypter) CryptBlocks(dst, src []byte) {
	// Note: since this is used only with Go's built-in AES encrypt/decrypt, which checks for incomplete overlap, I'm
	// not going to dive into it here.
	if len(src)%m.blockSize != 0 {
		panic("ECB EncryptBlocks: length of src is not a multiple of block size")
	}

	if len(dst) < len(src) {
		panic("ECB CryptBlocks: dst and src are of different sizes")
	}

	for i := 0; i < len(src); i += m.blockSize {
		m.b.Encrypt(dst[i:i+m.blockSize], src[i:i+m.blockSize])
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (m *ecbDecrypter) BlockSize() int { return m.blockSize }

func (m *ecbDecrypter) CryptBlocks(dst, src []byte) {
	// Note: since this is used only with Go's built-in AES encrypt/decrypt, which checks for incomplete overlap, I'm
	// not going to dive into it here.
	if len(src)%m.blockSize != 0 {
		panic("ECB DecryptBlocks: length of src is not a multiple of block size")
	}

	if len(dst) < len(src) {
		panic("ECB DecryptBlocks: dst and src are of different sizes")
	}

	for i := 0; i < len(src); i += m.blockSize {
		m.b.Decrypt(dst[i:i+m.blockSize], src[i:i+m.blockSize])
	}
}
