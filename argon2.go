package argon2

import (
	"hash"
	"testing"

	"github.com/dchest/blake2b"
)

const version uint32 = 0x10

/*

inputs:

 P message
 S nonce
 K secret key (optional)
 X associated data (optional)

 p parallelism
 m memory size
 n iterations

*/

func argon2(output, P, S, K, X []byte, p, m, n uint32, t *testing.T) []byte {
	if p == 0 || m == 0 || n == 0 {
		panic("argon: internal error: invalid params")
	}
	if m%(p*4) != 0 {
		panic("argon: internal error: invalid m")
	}

	m0 := m
	if m < 8*p {
		m = 8 * p
	}

	// Argon2 operates over a matrix of 1024-byte blocks
	b := make([][128]uint64, m)
	q := m / p
	g := q / 4

	// Compute a hash of all the input parameters
	var buf [72]byte
	var h0 [1024]byte

	h := blake2b.New512()
	write32(h, p)
	write32(h, uint32(len(output)))
	write32(h, m0)
	write32(h, n)
	write32(h, version)
	write32(h, 0) // y = argon2d
	write32(h, uint32(len(P)))
	h.Write(P)
	write32(h, uint32(len(S)))
	h.Write(S)
	write32(h, uint32(len(K)))
	h.Write(K)
	write32(h, uint32(len(X)))
	h.Write(X)
	h.Sum(buf[:0])
	h.Reset()

	// Use the hash to initialize the first two columns of the matrix
	for lane := uint32(0); lane < p; lane++ {
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
		t.Logf("Iterations: %d, Memory: %d KiB, Parallelism: %d lanes, Tag length: %d bytes", n, m, p, len(output))
		t.Logf("Password[%d]: % x", len(P), P)
		t.Logf("Nonce[%d]: % x", len(S), S)
		t.Logf("Secret[%d]: % x", len(K), K)
		t.Logf("Associated data[%d]: % x", len(X), X)
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
			for lane := uint32(0); lane < p; lane++ {
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

					rand := b[prev][0]
					rslice, rlane, ri := index(rand, q, g, p, k, slice, lane, i, t)
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
	for lane := uint32(0); lane < p-1; lane++ {
		for i, v := range b[lane*q+q-1] {
			b[m-1][i] ^= v
		}
	}

	// Output
	for i, v := range b[m-1] {
		h0[i*8] = uint8(v)
		h0[i*8+1] = uint8(v >> 8)
		h0[i*8+2] = uint8(v >> 16)
		h0[i*8+3] = uint8(v >> 24)
		h0[i*8+4] = uint8(v >> 32)
		h0[i*8+5] = uint8(v >> 40)
		h0[i*8+6] = uint8(v >> 48)
		h0[i*8+7] = uint8(v >> 56)
	}
	blake2b_long(output, h0[:])
	if t != nil {
		t.Logf("Output: % X", output)
	}
	return output
}

func index(rand uint64, q, g, p, k, slice, lane, i uint32, t *testing.T) (rslice, rlane, ri uint32) {
	rlane = uint32(rand>>32) % p

	var start, max uint32
	if k == 0 {
		start = 0
		if slice == 0 || lane == rlane {
			// All blocks in this lane so far
			max = slice*g + i
		} else {
			// All blocks in another lane
			// in slices prior to the current slice
			max = slice * g
		}
	} else {
		start = (slice + 1) % 4 * g
		if lane == rlane {
			// All blocks in this lane
			max = 3*g + i
		} else {
			// All blocks in another lane
			// except the current slice
			max = 3 * g
		}
	}
	if i == 0 || lane == rlane {
		max -= 1
	}

	phi := rand & 0xFFFFFFFF
	phi = phi * phi >> 32
	phi = phi * uint64(max) >> 32
	ri = uint32((uint64(start) + uint64(max) - 1 - phi) % uint64(q))

	if t != nil {
		i0 := lane*q + slice*g + i
		j0 := rlane*q + ri
		t.Logf("  i = %d(%d,%d,%d), rand = %d, max = %d, start = %d, phi = %d, j = %d(%d,%d,%d)", i0, lane, slice, i, rand, max, start, phi, j0, rlane, rslice, ri)
	}

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

func write32(h hash.Hash, v uint32) (n int, err error) {
	var b [4]byte
	b[0] = uint8(v)
	b[1] = uint8(v >> 8)
	b[2] = uint8(v >> 16)
	b[3] = uint8(v >> 24)
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
