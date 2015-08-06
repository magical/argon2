package argon

import (
	"testing"
)

func TestArgon2(t *testing.T) {
	var out [8]byte
	var msg [16]byte
	var salt = [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	argon2(out[:], msg[:], salt[:], nil, nil, 1, 8, 3, t)
	want := [8]byte{0xd7, 0xfc, 0x89, 0xfa, 0x6f, 0x75, 0xa9, 0xf3}
	if want != out {
		t.Errorf("got % x, want % x\n", out, want)
	}
}

func TestArgon2_100KB(t *testing.T) {
	var out [8]byte
	var msg [16]byte
	var salt = [8]byte{1,1,1,1,1,1,1,1}
	argon2(out[:], msg[:], salt[:], nil, nil, 1, 100, 3, t)
	want := [8]byte{0x8c, 0xba, 0x3f, 0x76, 0xc6, 0x69, 0x66, 0xa6}
	if want != out {
		t.Errorf("got % x, want % x\n", out, want)
	}
}
