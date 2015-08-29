package argon2

import (
	"bytes"
	"testing"
)

func mk(n int, v uint8) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestArgon_vec(t *testing.T) {
	msg := mk(32, 0x1)
	salt := mk(16, 0x2)
	key := mk(8, 0x3)
	data := mk(12, 0x4)
	want := []byte{0x57, 0xb0, 0x61, 0x3b, 0xfd, 0xd4, 0x13, 0x1a, 0x0c, 0x34, 0x88, 0x34, 0xc6, 0x72, 0x9c, 0x2c, 0x72, 0x29, 0x92, 0x1e, 0x6b, 0xba, 0x37, 0x66, 0x5d, 0x97, 0x8c, 0x4f, 0xe7, 0x17, 0x5e, 0xd2}
	out := make([]byte, len(want))
	argon2(out[:], msg, salt, key, data, 4, 16, 3, t)
	if !bytes.Equal(want, out) {
		t.Errorf("p=4, mem=16, n=3: got % x, want % x\n", out, want)
	}
}

func testArgon(t *testing.T, par, mem uint32, want []byte) {
	msg := mk(16, 0)
	salt := mk(8, 1)

	out := make([]byte, len(want))
	argon2(out[:], msg, salt, nil, nil, par, mem, 3, t)
	if !bytes.Equal(want, out) {
		t.Errorf("p=%d, mem=%d: got % x, want % x\n", par, mem, out, want)
	}
}

func TestArgon_8KB(t *testing.T) {
	testArgon(t, 1, 8, []byte{0x01, 0x99, 0x83, 0x87, 0x43, 0xcd, 0xe9, 0x08})
}
func TestArgon_100KB(t *testing.T) {
	testArgon(t, 1, 100, []byte{0x4a, 0x5c, 0xc5, 0x4a, 0x8e, 0xae, 0x2b, 0x45})

}
func TestArgon_16KB_P2(t *testing.T) {
	testArgon(t, 2, 16, []byte{0xc4, 0xa5, 0xdd, 0x0b, 0xe8, 0x8e, 0x55, 0x73})
}
func TestArgon_128KB_P16(t *testing.T) {
	testArgon(t, 16, 128, []byte{0x3d, 0x78, 0x1e, 0xd8, 0xd3, 0x91, 0xfa, 0x87})
}
func TestArgon_512KB_P64(t *testing.T) {
	testArgon(t, 64, 512, []byte{0xc4, 0xd6, 0x86, 0xce, 0x05, 0x61, 0x2c, 0x05})
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
