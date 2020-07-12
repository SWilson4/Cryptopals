package s2

type Padder interface {
	pad([]byte) []byte
	unpad([]byte) []byte
}
