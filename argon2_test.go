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
func TestArgon_128KB_P16(t *testing.T) {
	testArgon(t, 16, 128, [8]byte{0x5a, 0x52, 0x9a, 0x86, 0xad, 0x14, 0x02, 0xb2})
}
func TestArgon_512KB_P64(t *testing.T) {
	testArgon(t, 64, 512, [8]byte{0xf3, 0x30, 0x6e, 0xa7, 0x00, 0x9a, 0xe1, 0xc1})
}

func benchArgon(b *testing.B, par uint8, mem, n uint32) {
	var msg [16]byte
	var salt = [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	var out [8]byte
	for i := 0; i < b.N; i++ {
		argon2(out[:], msg[:], salt[:], nil, nil, uint32(par), mem, n, nil)
	}
}

func BenchmarkArgon_8KB_3N(b *testing.B)   { benchArgon(b, 1, 8, 3) }
func BenchmarkArgon_8KB_100N(b *testing.B) { benchArgon(b, 1, 8, 100) }
func BenchmarkArgon_128KB_1P(b *testing.B) { benchArgon(b, 1, 128, 3) }
func BenchmarkArgon_128KB_4P(b *testing.B) { benchArgon(b, 4, 128, 3) }
