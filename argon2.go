package argon

import (
	"hash"
	"testing"

	"github.com/dchest/blake2b"
)

const version uint8 = 0x10

/*

inputs:

 P message
 S nonce
 K secret key (optional)
 X associated data (optional)

 d parallelism
 m memory size
 n iterations

*/

func argon2(output, P, S, K, X []byte, d, m, n uint32, t *testing.T) []byte {
	if d == 0 || m == 0 || n == 0 {
		panic("argon: internal error: invalid params")
	}
	if m%(d*4) != 0 {
		panic("argon: internal error: invalid m")
	}

	// Argon2 operates over a matrix of 1024-byte blocks
	b := make([][128]uint64, m)
	q := m / d
	g := q / 4

	// Compute a hash of all the input parameters
	var buf [72]byte
	var h0 [1024]byte

	h := blake2b.New512()
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
	h.Sum(buf[:0])
	h.Reset()

	// Use the hash to initialize the first two columns of the matrix
	for lane := uint32(0); lane < d; lane++ {
		buf[68] = uint8(lane)
		buf[69] = uint8(lane >> 8)
		buf[70] = uint8(lane >> 16)
		buf[71] = uint8(lane >> 24)

		buf[64] = 0
		blake2b_long(h0[:], buf[:72])
		for i := range b[0] {
			b[lane*q+0][i] = read64(h0[i*8:])
		}

		buf[64] = 1
		blake2b_long(h0[:], buf[:72])
		for i := range b[0] {
			b[lane*q+1][i] = read64(h0[i*8:])
		}
	}

	if t != nil {
		t.Logf("Iterations: %d, Memory: %d KiB, Parallelism: %d lanes, Tag length: %d bytes", n, m, d, len(output))
		t.Logf("Message: % x", P)
		t.Logf("Nonce: % x", S)
		t.Logf("Input hash: % x", buf[:64])
	}

	for i := range buf {
		buf[i] = 0
	}

	// Get down to business
	for k := uint32(0); k < n; k++ {
		if t != nil {
			t.Log()
			t.Logf(" After pass %d:", k)
		}
		for slice := uint32(0); slice < 4; slice++ {
			for lane := uint32(0); lane < d; lane++ {
				i := uint32(0)
				if k == 0 && slice == 0 {
					i = 2
				}
				j := lane*q + slice*g + i
				for ; i < g; i, j = i+1, j+1 {
					prev := j - 1
					if i == 0 && slice == 0 {
						prev = lane*q + q - 1
					}

					rand := uint32(b[prev][0])
					rslice, rlane, ri := index(rand, q, g, d, k, slice, lane, i)
					j0 := rlane*q + rslice*g + ri

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

	// XOR the blocks in the last column together
	for lane := uint32(0); lane < d-1; lane++ {
		for i, v := range b[lane*q+q-1] {
			b[m-1][i] ^= v
		}
	}

	// Output
	for i, v := range b[m-1] {
		h0[i*8] = uint8(v)
		h0[i*8+1] = uint8(v>>8)
		h0[i*8+2] = uint8(v>>16)
		h0[i*8+3] = uint8(v>>24)
		h0[i*8+4] = uint8(v>>32)
		h0[i*8+5] = uint8(v>>40)
		h0[i*8+6] = uint8(v>>48)
		h0[i*8+7] = uint8(v>>56)
	}
	blake2b_long(output, h0[:])
	if t != nil {
		t.Logf("Output: % X", output)
	}
	return output
}

func index(rand, q, g, d, k, slice, lane, i uint32) (rslice, rlane, ri uint32) {
	// Each block is computed from the previous block
	// and a random block.
	//
	// There are restrictions on the random block,
	// leading to gaps in the selection, leading to
	// the following incredibly awkward calculations.

	var cut0, cut1, max uint32
	if k == 0 {
		// 1. First pass: include all blocks before the current slice
		cut0 = slice * g * d
		cut1 = cut0
	} else {
		// 2. Later passes: include all blocks not in the current slice
		cut0 = slice * g * d
		cut1 = 3 * g * d
	}
	if i != 0 {
		// 3. Include all blocks in the current segment (before the current block)
		// except the immediately prior block
		max = cut1 + i - 1
	} else {
		// 4. For the first block of each segment,
		// exclude the last block of every lane
		// of the previous slice.
		if slice > 0 {
			cut0 -= d
		}
		cut1 -= d
		max = cut1
	}

	// Now that we've selected the block, figure out where it actually is.
	// Blocks are enumerated by slice, then lane, then block,
	// as if b were [4][d][q/4]block.
	j := rand % max

	if j < cut1 {
		if j < cut0 {
			rslice = j / (g * d)
		} else {
			j -= cut0
			rslice = j/(g*d) + slice + 1
		}
		if i == 0 && rslice == slice-1 {
			j -= rslice * g * d
			rlane = j / (g - 1) % d
			ri = j % (g - 1)
		} else if i == 0 && slice == 0 && rslice == 3 {
			j -= 2 * g * d
			rlane = j / (g - 1) % d
			ri = j % (g - 1)
		} else {
			rlane = j / g % d
			ri = j % g
		}
	} else {
		rslice = slice
		rlane = lane
		ri = j - cut1
	}

	//if t != nil {
	//	t.Logf("  i = %d, prev = %d, rand = %d, cut0 = %d, cut1 = %d, max = %d, orig = %d, j = %d(%d,%d,%d)", j, prev, rand, cut0, cut1, max, rand%max, j0, rlane, rslice, ri)
	//}

	return rslice, rlane, ri
}

func blake2b_long(out, in []byte) {
	if len(out) < blake2b.Size {
		h, err := blake2b.New(&blake2b.Config{Size: uint8(len(out))})
		if err != nil {
			panic(err)
		}
		write32(h, uint32(len(out)))
		h.Write(in)
		h.Sum(out[:0])
		return
	}

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
