package argon

import (
	"testing"
)

func testArgon(t *testing.T, par uint8, mem uint32, want [8]byte) {
	var msg [16]byte
	var salt = [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	var out [8]byte
	argon2(out[:], msg[:], salt[:], nil, nil, uint32(par), mem, 3, t)
	if want != out {
		t.Errorf("p=%d, mem=%d: got % x, want % x\n", par, mem, out, want)
	}
}

func TestArgon_8KB(t *testing.T) {
	testArgon(t, 1, 8, [8]byte{0xd7, 0xfc, 0x89, 0xfa, 0x6f, 0x75, 0xa9, 0xf3})
}
func TestArgon_100KB(t *testing.T) {
	testArgon(t, 1, 100, [8]byte{0x8c, 0xba, 0x3f, 0x76, 0xc6, 0x69, 0x66, 0xa6})
}
func TestArgon_16KB_P2(t *testing.T) {
	testArgon(t, 2, 16, [8]byte{0xcb, 0x85, 0x0e, 0x0f, 0xc4, 0xa1, 0xd0, 0x9d})
}
