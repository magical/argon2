package argon

import (
	"fmt"
	"testing"
)

func TestArgon2(t *testing.T) {
	var out [8]byte
	var msg [16]byte
	var salt = [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	argon2(out[:], msg[:], salt[:], nil, nil, 1, 8, 3)
	fmt.Printf("Output: % X\n", out[:])
}
