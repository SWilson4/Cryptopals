package block

type padder interface {
	pad([]byte) []byte
	unpad([]byte) []byte
}

type pkcs struct{ blockSize uint8 }

func newPKCS(blockSize uint8) padder {
	return &pkcs{blockSize}
}

// Pads rawBytes to have length divisible by p.blockSize by appending bytes whose value is the number of bytes required.
// If the length of rawBytes is divisible by p.blockSize, p.blockSize bytes are appended.
func (p *pkcs) pad(rawBytes []byte) []byte {
	toAdd := int(p.blockSize) - len(rawBytes)%int(p.blockSize)
	for i := 0; i < toAdd; i++ {
		rawBytes = append(rawBytes, byte(toAdd))
	}
	return rawBytes
}

// Undoes the pad operation and panics if this is not possible.
func (p *pkcs) unpad(rawBytes []byte) []byte {
	if len(rawBytes) == 0 {
		panic("PKCS Unpad: zero-length input")
	}

	toRemove := int(rawBytes[len(rawBytes)-1])
	if toRemove > len(rawBytes) {
		panic("PKCS Unpad: input is not padded properly")
	}

	for i := len(rawBytes) - 1; i >= len(rawBytes)-toRemove; i-- {
		if rawBytes[i] != byte(toRemove) {
			panic("PKCS Unpad: input is not padded properly")
		}
	}

	return rawBytes[:len(rawBytes)-toRemove]
}
