package argon

/*

inputs:

 P message
 S nonce

 d parallelism
 t "tag" length (output length)
 m memory size
 n iterations
 v version number
 K secret value
 X associated data

functions

 H the Blake2b hash function
 G compression function

*/

import (
	"fmt"
	"hash"
	"testing"

	"github.com/dchest/blake2b"
)

const version uint8 = 0x10

func argon2(output, P, S, K, X []byte, d uint8, m, n uint32, t *testing.T) []byte {
	if d != 1 {
		panic("argon: parallelism not supported")
	}
	h := blake2b.New512()
	write8(h, d)
	write32(h, uint32(len(output)))
	write32(h, m)
	write32(h, n)
	write8(h, version)
	write32(h, uint32(len(P)))
	h.Write(P)
	write32(h, uint32(len(S)))
	h.Write(S)
	write8(h, uint8(len(K)))
	h.Write(K)
	write32(h, uint32(len(X)))
	h.Write(X)

	var buf [72]byte
	h.Sum(buf[:0])
	h.Reset()

	if t != nil {
		t.Logf("Iterations: %d, Memory: %d KiBytes, Parallelism: %d lanes, Tag length: %d bytes", n, m, d, len(output))
		t.Logf("Message: % x", P)
		t.Logf("Nonce: % x", S)
		t.Logf("Input hash: % x", buf[:64])
	}

	// [128]uint64 is 1024 bytes
	b := make([][128]uint64, m)
	var h0 [1024]byte

	q := m / uint32(d)
	for k := uint32(0); k < n; k++ {
		var i uint32
		var start uint32
		if k == 0 {
			buf[64] = 0
			buf[68] = uint8(i)
			buf[69] = uint8(i>>8)
			buf[70] = uint8(i>>16)
			buf[71] = uint8(i>>24)
			blake2b_long(h0[:], buf[:72])
			for i := range b[0] {
				b[0][i] = read64(h0[i*8:])
			}

			buf[64] = 1
			blake2b_long(h0[:], buf[:72])
			for i := range b[1] {
				b[1][i] = read64(h0[i*8:])
			}
			start = 2
		}
		for j := start; j < q; j++ {
			prev := j - 1
			if j == 0 {
				prev = q - 1
			}
			// Each block is computed from the previous block
			// and a random other block.
			// But there are restrictions on which blocks we can
			// use, so we have to perform the most awkward index
			// calculation ever.
			s := j / (q / 4)
			var j0, cut0, cut1, max uint32

			first := j == s*(q/4)

			if k == 0 {
				// All blocks before the current slice
				max += (q / 4) * s
				cut0 = max
				cut1 = max
			} else {
				// All blocks not in the current slice
				max += (q / 4) * 3
				cut0 = (q / 4) * s
				cut1 = max
			}

			// All blocks in the current segment except the previous
			max += j - s*(q/4) - 1

			var extra uint32
			if first && s != 0 {
				// The first block in a segment
				// cannot reference the last block of any lane
				cut0 -= 1
				cut1 -= 1
				extra = 1
			}

			rand := uint32(b[prev][0])
			j0 = rand % max
			// TODO slices are enumerated first in the p direction.
			// As if the matrix were [4][p][q/4]block
			if j0 < cut0 {
				j0 += 0
			} else if j0 < cut1 {
				j0 += q / 4 + extra
			} else {
				j0 = j0 - cut1 + (s * (q / 4))
			}

			if j0 > q {
				fmt.Println("i, j, q, s, cut0, cut1, max, rand, j0")
				fmt.Println(i, j, q, s, cut0, cut1, max, rand, j0)
				panic("")
			}

			if t != nil {
				t.Logf("prev = %d, rand = %d, cut0 = %d, cut1 = %d, max = %d, j = %d", prev, rand, cut0, cut1, max, j0)
			}

			block(&b[j], &b[prev], &b[j0])
		}
		if t != nil {
			t.Log()
			t.Logf(" After pass %d:", k)
			for i := range b {
				t.Logf("  Block %.4d [0]: %x", i, b[i][0])
			}
		}
	}
	h, err := blake2b.New(&blake2b.Config{Size: uint8(len(output))})
	if err != nil {
		panic(err)
	}
	write32(h, uint32(len(output)))
	for _, v := range b[m-1] {
		write64(h, v)
	}
	h.Sum(output[:0])
	if t != nil {
		t.Logf("Output: % X", output)
	}
	return output
}

func blake2b_long(out, in []byte) {
	var buf [64]byte
	h := blake2b.New512()
	h.Reset()
	write32(h, uint32(len(out)))
	h.Write(in)
	h.Sum(buf[:0])
	copy(out, buf[:32])
	var n int
	for n = 32; n < len(out)-64; n += 32 {
		h.Reset()
		h.Write(buf[:])
		h.Sum(buf[:0])
		copy(out[n:], buf[:32])
	}
	h.Reset()
	h.Write(buf[:])
	h.Sum(buf[:0])
	copy(out[n:], buf[:])
}

/*
func index(k, i, j, r, s, p, q uint32) {
	l := 4
	n := 0
	// all blocks of segments Q[r'][*] where r' < r
	n += r * p * q / l
	// if second or later pass over memory,
	// all blocks of segments Q[r'][*] where r' > r
	if k > 0 {
		n += (l-r)*p - 1
	}
	// all blocks of segment of the current segment Q[r][s]
	// except the previous block
	n += q - 1
	//
}
*/

func block(z, a, b *[128]uint64) {
	// .,+16dread !python round.py
	for i := range z {
		z[i] = a[i]^b[i]
	}

	for i := 0; i < 128; i += 16 {
		z[i+0], z[i+1], z[i+2], z[i+3], z[i+4], z[i+5], z[i+6], z[i+7], z[i+8], z[i+9], z[i+10], z[i+11], z[i+12], z[i+13], z[i+14], z[i+15] = _P(z[i+0], z[i+1], z[i+2], z[i+3], z[i+4], z[i+5], z[i+6], z[i+7], z[i+8], z[i+9], z[i+10], z[i+11], z[i+12], z[i+13], z[i+14], z[i+15])
	}

	for i := 0; i < 16; i += 2 {
		z[i+0], z[i+1], z[i+16], z[i+17], z[i+32], z[i+33], z[i+48], z[i+49], z[i+64], z[i+65], z[i+80], z[i+81], z[i+96], z[i+97], z[i+112], z[i+113] = _P(z[i+0], z[i+1], z[i+16], z[i+17], z[i+32], z[i+33], z[i+48], z[i+49], z[i+64], z[i+65], z[i+80], z[i+81], z[i+96], z[i+97], z[i+112], z[i+113])
	}

	for i := range z {
		z[i] ^= a[i] ^ b[i]
	}
}

func _P(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 uint64) (z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15 uint64) {
	v0, v4, v8, v12 = _G(v0, v4, v8, v12)
	v1, v5, v9, v13 = _G(v1, v5, v9, v13)
	v2, v6, v10, v14 = _G(v2, v6, v10, v14)
	v3, v7, v11, v15 = _G(v3, v7, v11, v15)
	v0, v5, v10, v15 = _G(v0, v5, v10, v15)
	v1, v6, v11, v12 = _G(v1, v6, v11, v12)
	v2, v7, v8, v13 = _G(v2, v7, v8, v13)
	v3, v4, v9, v14 = _G(v3, v4, v9, v14)
	return v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
}

func _G(a, b, c, d uint64) (x, y, z, w uint64) {
	a = a + b
	d = ror(d^a, 32)
	c = c + d
	b = ror(b^c, 24)
	a = a + b
	d = ror(d^a, 16)
	c = c + d
	b = ror(b^c, 63)
	return a, b, c, d
}

func ror(a uint64, r uint) uint64 {
	return a>>r | a<<(64-r)
}

func write8(h hash.Hash, v uint8) (n int, err error) {
	var b [1]byte
	b[0] = v
	return h.Write(b[:])
}

func write32(h hash.Hash, v uint32) (n int, err error) {
	var b [4]byte
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	b[2] = uint8(v >> 16)
	b[3] = uint8(v >> 24)
	return h.Write(b[:])
}

func write64(h hash.Hash, v uint64) (n int, err error) {
	var b [8]byte
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	b[2] = uint8(v >> 16)
	b[3] = uint8(v >> 24)
	b[4] = uint8(v >> 32)
	b[5] = uint8(v >> 40)
	b[6] = uint8(v >> 48)
	b[7] = uint8(v >> 56)
	return h.Write(b[:])
}

func read64(b []uint8) uint64 {
	return uint64(b[0]) |
		uint64(b[1])<<8 |
		uint64(b[2])<<16 |
		uint64(b[3])<<24 |
		uint64(b[4])<<32 |
		uint64(b[5])<<40 |
		uint64(b[6])<<48 |
		uint64(b[7])<<56
}
