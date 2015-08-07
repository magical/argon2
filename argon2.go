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
	"hash"
	"testing"

	"github.com/dchest/blake2b"
)

const version uint8 = 0x10

func argon2(output, P, S, K, X []byte, d, m, n uint32, t *testing.T) []byte {
	if m%(d*4) != 0 {
		panic("argon: invalid memory parameter")
	}
	h := blake2b.New512()
	// TODO check lengths and ranges
	write8(h, uint8(d))
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

	// Argon2 operates over a matrix of 1024-byte blocks
	// The matrix is divided into lanes, slices, and segments.
	b := make([][128]uint64, m)

	var h0 [1024]byte

	q := m / d
	q4 := q / 4
	for k := uint32(0); k < n; k++ {
		if t != nil {
			t.Log()
			t.Logf(" After pass %d:", k)
		}
		//for s := uint32(0); s < 4; s++ {
		for slice := uint32(0); slice < 4; slice++ {
			//for i := uint32(0); i < d; i++ {
			for lane := uint32(0); lane < d; lane++ {
				i := uint32(0)
				seg := lane*q + slice*q4
				_ = seg
				j := lane*q + slice*q4
				if k == 0 && slice == 0 {
					t.Log(slice, lane, i, j)
					buf[64] = 0
					buf[68] = uint8(lane)
					buf[69] = uint8(lane >> 8)
					buf[70] = uint8(lane >> 16)
					buf[71] = uint8(lane >> 24)
					blake2b_long(h0[:], buf[:72])
					for i := range b[j+0] {
						b[j+0][i] = read64(h0[i*8:])
					}

					buf[64] = 1
					blake2b_long(h0[:], buf[:72])
					for i := range b[j+1] {
						b[j+1][i] = read64(h0[i*8:])
					}
					i = 2
					j += 2
				}
				for ; i < q4; i, j = i+1, j+1 {
					prev := j - 1
					if i == 0 && slice == 0 {
						prev = lane*q + q - 1
					}

					// Each block is computed from the previous block
					// and a random block.
					//
					// There are restrictions on the random block,
					// leading to gaps in the selection, leading to
					// the following incredibly awkward calculations.

					var j0, cut0, cut1, max uint32
					if k == 0 {
						// 1. First pass: include all blocks before the current slice
						max += q4 * slice * d
						cut0 = max
						cut1 = max
					} else {
						// 2. Later passes: include all blocks not in the current slice
						max += q4 * 3 * d
						cut0 = q4 * slice * d
						cut1 = max
					}
					// 3. Include all blocks in the current segment (before the current block)
					// except the immediately prior block
					if i != 0 {
						max += i - 1
					}

					if i == 0 {
						// 4. For the first block of each segment,
						// exclude the last block of every lane
						// in the previous slice.
						if cut0 > d {
							cut0 -= d
						}
						cut1 -= d
						max -= d
					}

					rand := uint32(b[prev][0])
					j0 = rand % max

					// Now that we've selected the block, figure out where it actually is.
					// Blocks are enumerated by slice, then lane, then block,
					// as if the matrix were [4][d][q/4]block.
					var rslice, rlane, ri uint32
					if j0 < cut0 {
						rslice = j0 / (q4 * d)
						if i == 0 && rslice == slice-1 {
							j0 -= rslice * q4 * d
							rlane = j0 / (q4 - 1) % d
							ri = j0 % (q4 - 1)
						} else {
							rlane = j0 / q4 % d
							ri = j0 % q4
						}
						j0 = rlane*q + rslice*q4 + ri
					} else if j0 < cut1 {
						j0 -= cut0
						rslice = j0 / (q4 * d)
						if i == 0 && slice == 0 && rslice == 3 {
							j0 -= rslice * q4 * d
							rlane = j0 / (q4 - 1) % d
							ri = j0 % (q4 - 1)
						} else {
							rlane = j0 / q4 % d
							ri = j0 % q4
						}
						rslice += slice + 1
						j0 = rlane*q + rslice*q4 + ri
					} else {
						j0 = j0 - cut1 + lane*q + slice*q4
						rslice = slice
						rlane = lane
						ri = j0 - cut1
					}

					if t != nil {
						t.Logf("  i = %d, prev = %d, rand = %d, cut0 = %d, cut1 = %d, max = %d, orig = %d, j = %d(%d,%d,%d)", j, prev, rand, cut0, cut1, max, rand%max, j0, rlane, rslice, ri)
					}

					if j0 > m {
						panic("argon: internal error: bad j0")
					}

					block(&b[j], &b[prev], &b[j0])
				}
			}
		}
		if t != nil {
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
	for lane := uint32(0); lane < d-1; lane++ {
		for i, v := range b[lane*q+q-1] {
			b[m-1][i] ^= v
		}
	}
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
		z[i] = a[i] ^ b[i]
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
