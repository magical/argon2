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
		panic("argon: internal error: invalid m")
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
	g := q / 4
	for k := uint32(0); k < n; k++ {
		if t != nil {
			t.Log()
			t.Logf(" After pass %d:", k)
		}
		for slice := uint32(0); slice < 4; slice++ {
			for lane := uint32(0); lane < d; lane++ {
				i := uint32(0)
				j := lane*q + slice*g
				if k == 0 && slice == 0 {
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
				for ; i < g; i, j = i+1, j+1 {
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
						max += g * slice * d
						cut0 = max
						cut1 = max
					} else {
						// 2. Later passes: include all blocks not in the current slice
						max += g * 3 * d
						cut0 = g * slice * d
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
						rslice = j0 / (g * d)
						if i == 0 && rslice == slice-1 {
							j0 -= rslice * g * d
							rlane = j0 / (g - 1) % d
							ri = j0 % (g - 1)
						} else {
							rlane = j0 / g % d
							ri = j0 % g
						}
						j0 = rlane*q + rslice*g + ri
					} else if j0 < cut1 {
						j0 -= cut0
						rslice = j0 / (g * d)
						if i == 0 && slice == 0 && rslice == 3 {
							j0 -= rslice * g * d
							rlane = j0 / (g - 1) % d
							ri = j0 % (g - 1)
						} else {
							rlane = j0 / g % d
							ri = j0 % g
						}
						rslice += slice + 1
						j0 = rlane*q + rslice*g + ri
					} else {
						j0 = j0 - cut1 + lane*q + slice*g
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
