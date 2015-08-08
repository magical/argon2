package argon

import (
	"fmt"
	"strings"
	"testing"
)

var zeros [16]byte
var ones = [8]byte{1, 1, 1, 1, 1, 1, 1, 1}

// Fake salt function for the example
func randomSalt() []byte {
	return ones[:8]
}

func ExampleKey() {
	pw := []byte("hunter2")
	salt := randomSalt()

	key, err := Key(pw, salt, 3, 1, 8192, 32)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%x", key)
	// Output: bd870ac43992d3709273f626141da5b7958a595a041326f153e9a9cc013fe6c4
}

var errorTests = []struct {
	pw   []byte
	salt []byte
	n    int
	mem  int
	par  int
	err  string
}{
	{
		pw: zeros[:1],
	},
}

func TestKeyErr(t *testing.T) {
	pw := zeros[:]
	salt := ones[:]

	want := "salt too short"
	_, err := Key(pw, salt[:1], 3, 1, 8192, 8)
	if err == nil {
		t.Errorf("got nil error, expected %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("got %q, expected %q", want)
	}

	want = "invalid par"
	_, err = Key(pw, salt, 3, 100, 8192, 8)
	if err == nil {
		t.Errorf("got nil error, expected %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("got %q, expected %q", want)
	}
}
