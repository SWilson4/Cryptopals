package s1

import (
	"encoding/hex"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	got, err := HexToBase64(in)
	if err != nil {
		t.Errorf("HexToBase64(%q) error: %v", in, err)
	} else if got != want {
		t.Errorf("HexToBase64(%q) == %q, want %q", in, got, want)
	}
}

func TestFixedXOR(t *testing.T) {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	want := "746865206b696420646f6e277420706c6179"
	got, err := FixedXOR(in1, in2)
	if err != nil {
		t.Errorf("FixedXOR(%q, %q) error: %v", in1, in2, err)
	} else if got != want {
		t.Errorf("FixedXOR(%q, %q) == %q, want %q", in1, in2, got, want)
	}
}

func TestBreakSingleByteXOR(t *testing.T) {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	var wantKey byte = 'X'
	wantMessage := "Cooking MC's like a pound of bacon"
	gotKey, gotMessage, err := BreakSingleByteXOR(in)
	if err != nil {
		t.Errorf("BreakSingleByteXOR(%q) error: %v", in, err)
	} else if gotKey != wantKey || wantMessage == gotMessage {
		t.Errorf("BreakSingleByteXOR(%q) == %q, %q; want %q, %q", in, gotKey, gotMessage, wantKey, wantMessage)
	}
}

func TestRepeatingKeyXOR(t *testing.T) {
	inPlaintext := hex.EncodeToString([]byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))
	inKey := hex.EncodeToString([]byte("ICE"))
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	got, err := RepeatingKeyXOR(inPlaintext, inKey)
	if err != nil {
		t.Errorf("RepeatingKeyXOR(%q, %q) error: %v", inPlaintext, inKey, err)
	} else if got != want {
		t.Errorf("RepeatingKeyXOR(%q, %q) == %q, want %q", inPlaintext, inKey, got, want)
	}
}

func TestHammingDistance(t *testing.T) {
	in1 := []byte("this is a test")
	in2 := []byte("wokka wokka!!!")
	want := 37
	got, err := hammingDistance(in1, in2)
	if err != nil {
		t.Errorf("hammingDistance(%q, %q) error: %v", in1, in2, err)
	} else if got != want {
		t.Errorf("hammingDistance(%q, %q) == %d, want %d", in1, in2, got, want)
	}
}

func TestCountRepeats(t *testing.T) {
	inBytes, _ := hex.DecodeString("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
	inSize := 16
	want := 3
	got := countRepeats(inBytes, inSize)
	if got != want {
		t.Errorf("countRepeats(%v, %d) == %d, want %d", inBytes, inSize, got, want)
	}
}

/*
func TestS1C1(t *testing.T) {
	if err := os.Chdir("c1"); err != nil {
		t.Errorf("s1c1: %v", err)
	}

	exp, err := os.Open("s1c1.out")
	if err != nil {
		t.Errorf("s1c1: %v", err)
	}
	defer exp.Close()

	tmp, err := ioutil.TempFile("", "output")
	if err != nil {
		t.Errorf("s1c1: %v", err)
	}
	defer os.Remove(tmp.Name())

	cmd := exec.Command("go run", "s1c1.go")
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		t.Errorf("s1c1: %v", err)
	}

	w := bufio.NewWriter(tmp)
	defer w.Flush()

	cmd := exec.Command("diff", tmp.Name(), exp.Name())
	if err != cmd.Run(); err != nil {
		t.Errorf("s1c1: %v", err)
	}
}
*/
