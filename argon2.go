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

	"github.com/dchest/blake2b"
)

const version uint8 = 0x10

func argon2(output, P, S, K, X []byte, d uint8, m, n uint32) []byte {
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

	var buf [64]byte
	h.Sum(buf[:0])
	h.Reset()

	fmt.Printf("Iterations: %d, Memory: %d KiBytes, Parallelism: %d lanes, Tag length: %d bytes\n", n, m, d, len(output))
	fmt.Printf("Message: % x\n", P)
	fmt.Printf("Nonce: % x\n", S)
	fmt.Printf("Input hash: % x\n", buf[:])

	// [128]uint64 is 1024 bytes
	b := make([][128]uint64, m)

	var h0, h1 [128]uint64
	h0[0] = read64(buf[0:])
	h0[1] = read64(buf[8:])
	h0[2] = read64(buf[16:])
	h0[3] = read64(buf[24:])

	q := m / uint32(d)
	for k := uint32(0); k < n; k++ {
		var i uint32
		if k == 0 {
			h1[0] = uint64(i) | 0<<32
			block(&b[0], &h0, &h1)
			h1[0] = uint64(i) | 1<<32
			block(&b[1], &h0, &h1)
		} else {
			j0 := 0
			block(&b[0], &b[q-1], &b[j0])
			block(&b[1], &b[0], &b[j0])
		}
		for j := uint32(2); j < q; j++ {
			// Each block is computed from the previous block
			// and a random other block.
			// But there are restrictions on which blocks we can
			// use, so we have to perform the most awkward index
			// calculation ever.
			s := j / (q / 4)
			var j0, cut0, cut1, max uint32

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
			max += q/4 - 1

			rand := uint32(b[j-1][0])
			j0 = rand % max
			if j0 < cut0 {
				// TODO slices are enumerated first in the p direction.
				// As if the matrix were [4][p][q/4]block

				j0 += 0
			} else if j0 < cut1 {
				j0 += q / 4
			} else {
				j0 = j0 - cut1 + (s * (q / 4))
			}

			if j0 > q {
				fmt.Println("i, j, q, s, cut0, cut1, max, rand, j0")
				fmt.Println(i, j, q, s, cut0, cut1, max, rand, j0)
				panic("")
			}

			block(&b[j], &b[j-1], &b[j0])
		}
	}
	for _, v := range b[n-1] {
		write64(h, v)
	}
	h.Sum(buf[:0])
	copy(output, buf[:])
	return output
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
	z[0], z[1], z[2], z[3], z[4], z[5], z[6], z[7], z[8], z[9], z[10], z[11], z[12], z[13], z[14], z[15] = _P(a[0]^b[0], a[1]^b[1], a[2]^b[2], a[3]^b[3], a[4]^b[4], a[5]^b[5], a[6]^b[6], a[7]^b[7], a[8]^b[8], a[9]^b[9], a[10]^b[10], a[11]^b[11], a[12]^b[12], a[13]^b[13], a[14]^b[14], a[15]^b[15])
	z[16], z[17], z[18], z[19], z[20], z[21], z[22], z[23], z[24], z[25], z[26], z[27], z[28], z[29], z[30], z[31] = _P(a[16]^b[16], a[17]^b[17], a[18]^b[18], a[19]^b[19], a[20]^b[20], a[21]^b[21], a[22]^b[22], a[23]^b[23], a[24]^b[24], a[25]^b[25], a[26]^b[26], a[27]^b[27], a[28]^b[28], a[29]^b[29], a[30]^b[30], a[31]^b[31])
	z[32], z[33], z[34], z[35], z[36], z[37], z[38], z[39], z[40], z[41], z[42], z[43], z[44], z[45], z[46], z[47] = _P(a[32]^b[32], a[33]^b[33], a[34]^b[34], a[35]^b[35], a[36]^b[36], a[37]^b[37], a[38]^b[38], a[39]^b[39], a[40]^b[40], a[41]^b[41], a[42]^b[42], a[43]^b[43], a[44]^b[44], a[45]^b[45], a[46]^b[46], a[47]^b[47])
	z[48], z[49], z[50], z[51], z[52], z[53], z[54], z[55], z[56], z[57], z[58], z[59], z[60], z[61], z[62], z[63] = _P(a[48]^b[48], a[49]^b[49], a[50]^b[50], a[51]^b[51], a[52]^b[52], a[53]^b[53], a[54]^b[54], a[55]^b[55], a[56]^b[56], a[57]^b[57], a[58]^b[58], a[59]^b[59], a[60]^b[60], a[61]^b[61], a[62]^b[62], a[63]^b[63])
	z[64], z[65], z[66], z[67], z[68], z[69], z[70], z[71], z[72], z[73], z[74], z[75], z[76], z[77], z[78], z[79] = _P(a[64]^b[64], a[65]^b[65], a[66]^b[66], a[67]^b[67], a[68]^b[68], a[69]^b[69], a[70]^b[70], a[71]^b[71], a[72]^b[72], a[73]^b[73], a[74]^b[74], a[75]^b[75], a[76]^b[76], a[77]^b[77], a[78]^b[78], a[79]^b[79])
	z[80], z[81], z[82], z[83], z[84], z[85], z[86], z[87], z[88], z[89], z[90], z[91], z[92], z[93], z[94], z[95] = _P(a[80]^b[80], a[81]^b[81], a[82]^b[82], a[83]^b[83], a[84]^b[84], a[85]^b[85], a[86]^b[86], a[87]^b[87], a[88]^b[88], a[89]^b[89], a[90]^b[90], a[91]^b[91], a[92]^b[92], a[93]^b[93], a[94]^b[94], a[95]^b[95])
	z[96], z[97], z[98], z[99], z[100], z[101], z[102], z[103], z[104], z[105], z[106], z[107], z[108], z[109], z[110], z[111] = _P(a[96]^b[96], a[97]^b[97], a[98]^b[98], a[99]^b[99], a[100]^b[100], a[101]^b[101], a[102]^b[102], a[103]^b[103], a[104]^b[104], a[105]^b[105], a[106]^b[106], a[107]^b[107], a[108]^b[108], a[109]^b[109], a[110]^b[110], a[111]^b[111])
	z[112], z[113], z[114], z[115], z[116], z[117], z[118], z[119], z[120], z[121], z[122], z[123], z[124], z[125], z[126], z[127] = _P(a[112]^b[112], a[113]^b[113], a[114]^b[114], a[115]^b[115], a[116]^b[116], a[117]^b[117], a[118]^b[118], a[119]^b[119], a[120]^b[120], a[121]^b[121], a[122]^b[122], a[123]^b[123], a[124]^b[124], a[125]^b[125], a[126]^b[126], a[127]^b[127])
	z[0], z[1], z[16], z[17], z[32], z[33], z[48], z[49], z[64], z[65], z[80], z[81], z[96], z[97], z[112], z[113] = _P(z[0], z[1], z[16], z[17], z[32], z[33], z[48], z[49], z[64], z[65], z[80], z[81], z[96], z[97], z[112], z[113])
	z[2], z[3], z[18], z[19], z[34], z[35], z[50], z[51], z[66], z[67], z[82], z[83], z[98], z[99], z[114], z[115] = _P(z[2], z[3], z[18], z[19], z[34], z[35], z[50], z[51], z[66], z[67], z[82], z[83], z[98], z[99], z[114], z[115])
	z[4], z[5], z[20], z[21], z[36], z[37], z[52], z[53], z[68], z[69], z[84], z[85], z[100], z[101], z[116], z[117] = _P(z[4], z[5], z[20], z[21], z[36], z[37], z[52], z[53], z[68], z[69], z[84], z[85], z[100], z[101], z[116], z[117])
	z[6], z[7], z[22], z[23], z[38], z[39], z[54], z[55], z[70], z[71], z[86], z[87], z[102], z[103], z[118], z[119] = _P(z[6], z[7], z[22], z[23], z[38], z[39], z[54], z[55], z[70], z[71], z[86], z[87], z[102], z[103], z[118], z[119])
	z[8], z[9], z[24], z[25], z[40], z[41], z[56], z[57], z[72], z[73], z[88], z[89], z[104], z[105], z[120], z[121] = _P(z[8], z[9], z[24], z[25], z[40], z[41], z[56], z[57], z[72], z[73], z[88], z[89], z[104], z[105], z[120], z[121])
	z[10], z[11], z[26], z[27], z[42], z[43], z[58], z[59], z[74], z[75], z[90], z[91], z[106], z[107], z[122], z[123] = _P(z[10], z[11], z[26], z[27], z[42], z[43], z[58], z[59], z[74], z[75], z[90], z[91], z[106], z[107], z[122], z[123])
	z[12], z[13], z[28], z[29], z[44], z[45], z[60], z[61], z[76], z[77], z[92], z[93], z[108], z[109], z[124], z[125] = _P(z[12], z[13], z[28], z[29], z[44], z[45], z[60], z[61], z[76], z[77], z[92], z[93], z[108], z[109], z[124], z[125])
	z[14], z[15], z[30], z[31], z[46], z[47], z[62], z[63], z[78], z[79], z[94], z[95], z[110], z[111], z[126], z[127] = _P(z[14], z[15], z[30], z[31], z[46], z[47], z[62], z[63], z[78], z[79], z[94], z[95], z[110], z[111], z[126], z[127])

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
