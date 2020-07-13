package s2

type padder interface {
	pad([]byte) []byte
	unpad([]byte) []byte
}
