package argon2

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

	key, err := Key(pw, salt, 3, 1, 8, 32)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%x", key)
	// Output: c15a7a43959a834f77714805434799ca8efdeb26ad0e1acda206af846a5cef29
}

func TestKeyErr(t *testing.T) {
	pw := zeros[:]
	salt := ones[:]

	want := "salt too short"
	_, err := Key(pw, salt[:1], 3, 1, 8, 8)
	if err == nil {
		t.Errorf("got nil error, expected %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("got %q, expected %q", err, want)
	}

	want = "invalid par"
	_, err = Key(pw, salt, 3, 256, 8, 8)
	if err == nil {
		t.Errorf("got nil error, expected %q", want)
	} else if !strings.Contains(err.Error(), want) {
		t.Errorf("got %q, expected %q", err, want)
	}
}
