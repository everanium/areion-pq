package main

import (
	"fmt"
	"math/bits"
	"math/rand/v2"

	"github.com/everanium/areion"
)

var rcP1 = [10][16]byte{
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
}

var rcP2 = [10][16]byte{
	{0x93, 0xe9, 0x72, 0x7c, 0xaf, 0x86, 0x54, 0xa1, 0xce, 0xe8, 0x41, 0x11, 0x34, 0x5c, 0xcc, 0xb4},
	{0xf6, 0x31, 0x18, 0x74, 0x5d, 0xc5, 0xa9, 0x2b, 0x2a, 0xbc, 0x6f, 0x63, 0x11, 0x14, 0xee, 0xb3},
	{0x5c, 0xcf, 0x24, 0x6c, 0x33, 0xba, 0xd6, 0xaf, 0x1e, 0x93, 0x87, 0x9b, 0x16, 0x3e, 0x5c, 0xce},
	{0xaf, 0xb9, 0x4b, 0x6b, 0x98, 0x48, 0x8f, 0x3b, 0x77, 0x86, 0x95, 0x28, 0x81, 0x53, 0x32, 0x7a},
	{0x91, 0xa9, 0x21, 0xfb, 0xcc, 0x09, 0xd8, 0x61, 0x93, 0x21, 0x28, 0x66, 0x1b, 0xe8, 0xbf, 0xc4},
	{0xb1, 0x75, 0x85, 0xe9, 0x5d, 0x5d, 0x84, 0xef, 0x32, 0x80, 0xec, 0x5d, 0x60, 0xac, 0x7c, 0x48},
	{0xc5, 0xac, 0x96, 0xd3, 0x81, 0x3e, 0x89, 0x23, 0x88, 0x1b, 0x65, 0xeb, 0x02, 0x23, 0x26, 0xdc},
	{0x40, 0x00, 0x42, 0x48, 0x2a, 0x48, 0xb4, 0xe0, 0x92, 0x23, 0x44, 0x3f, 0x38, 0xff, 0xd6, 0xf6},
	{0x9a, 0x6c, 0xe9, 0xf6, 0x42, 0x68, 0xc6, 0x21, 0x5e, 0x9b, 0x1f, 0x9e, 0x4a, 0xf0, 0xc8, 0x69},
	{0x68, 0x2f, 0x54, 0xd8, 0xd2, 0xa0, 0x51, 0x6a, 0xf0, 0x88, 0xd3, 0xab, 0x61, 0x9c, 0x0c, 0x67},
}

func gf256Mul(a, b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		mask := -((b >> i) & 1)
		r ^= a & mask
		hi := -((a >> 7) & 1)
		a = (a << 1) ^ (0x1b & hi)
	}
	return r
}

func gf256Sq(a byte) byte {
	return gf256Mul(a, a)
}

func gf256Inv(a byte) byte {
	x2 := gf256Sq(a)
	x3 := gf256Mul(x2, a)
	x6 := gf256Sq(x3)
	x12 := gf256Sq(x6)
	x15 := gf256Mul(x12, x3)
	x30 := gf256Sq(x15)
	x60 := gf256Sq(x30)
	x120 := gf256Sq(x60)
	x127 := gf256Mul(x120, x6)
	x127 = gf256Mul(x127, a)
	return gf256Sq(x127)
}

func gf256Affine(a byte) byte {
	return a ^ bits.RotateLeft8(a, 1) ^ bits.RotateLeft8(a, 2) ^ bits.RotateLeft8(a, 3) ^ bits.RotateLeft8(a, 4) ^ 0x63
}

func gf256AffineInv(s byte) byte {
	u := s ^ 0x63
	return bits.RotateLeft8(u, 1) ^ bits.RotateLeft8(u, 3) ^ bits.RotateLeft8(u, 6)
}

func aesInvShiftRows(b *[16]byte) (out [16]byte) {
	out[0], out[4], out[8], out[12] = b[0], b[4], b[8], b[12]
	out[1], out[5], out[9], out[13] = b[13], b[1], b[5], b[9]
	out[2], out[6], out[10], out[14] = b[10], b[14], b[2], b[6]
	out[3], out[7], out[11], out[15] = b[7], b[11], b[15], b[3]
	return out
}

func aesMixColumns(b *[16]byte) (out [16]byte) {
	for c := 0; c < 4; c++ {
		s0, s1, s2, s3 := b[4*c], b[4*c+1], b[4*c+2], b[4*c+3]
		out[4*c+0] = gf256Mul(s0, 2) ^ gf256Mul(s1, 3) ^ s2 ^ s3
		out[4*c+1] = s0 ^ gf256Mul(s1, 2) ^ gf256Mul(s2, 3) ^ s3
		out[4*c+2] = s0 ^ s1 ^ gf256Mul(s2, 2) ^ gf256Mul(s3, 3)
		out[4*c+3] = gf256Mul(s0, 3) ^ s1 ^ s2 ^ gf256Mul(s3, 2)
	}
	return out
}

func aesInvMixColumns(b *[16]byte) (out [16]byte) {
	for c := 0; c < 4; c++ {
		s0, s1, s2, s3 := b[4*c], b[4*c+1], b[4*c+2], b[4*c+3]
		out[4*c+0] = gf256Mul(s0, 14) ^ gf256Mul(s1, 11) ^ gf256Mul(s2, 13) ^ gf256Mul(s3, 9)
		out[4*c+1] = gf256Mul(s0, 9) ^ gf256Mul(s1, 14) ^ gf256Mul(s2, 11) ^ gf256Mul(s3, 13)
		out[4*c+2] = gf256Mul(s0, 13) ^ gf256Mul(s1, 9) ^ gf256Mul(s2, 14) ^ gf256Mul(s3, 11)
		out[4*c+3] = gf256Mul(s0, 11) ^ gf256Mul(s1, 13) ^ gf256Mul(s2, 9) ^ gf256Mul(s3, 14)
	}
	return out
}

func extractWitness256Ref(m, k1, k2 *[32]byte, rc *[10][16]byte) (c [32]byte, w [288]byte) {
	var x0, x1, zero [16]byte
	for i := 0; i < 16; i++ {
		x0[i] = m[i] ^ k1[i]
		x1[i] = m[16+i] ^ k1[16+i]
	}
	for r := 0; r < 10; r++ {
		var aNext, u, bNext [16]byte
		if r%2 == 0 {
			aNext = x0
			areion.AES128FinalRound(&aNext, &zero)
			u = x0
			areion.AES128Round(&u, &rc[r])
			bNext = u
			areion.AES128Round(&bNext, &x1)
			x0, x1 = aNext, bNext
		} else {
			aNext = x1
			areion.AES128FinalRound(&aNext, &zero)
			u = x1
			areion.AES128Round(&u, &rc[r])
			bNext = u
			areion.AES128Round(&bNext, &x0)
			x1, x0 = aNext, bNext
		}
		if r < 9 {
			copy(w[32*r:32*r+16], aNext[:])
			copy(w[32*r+16:32*r+32], bNext[:])
		}
	}
	for i := 0; i < 16; i++ {
		c[i] = x0[i] ^ k2[i]
		c[16+i] = x1[i] ^ k2[16+i]
	}
	return c, w
}

// verifySBoxLayerDegree2 checks all 16 S-boxes of a layer using ONLY the two
// QuickSilver degree-2 bilinear equations in GF(2^8):
//   C1(X, S) = Sq(X)*Y ^ X == 0
//   C2(X, S) = Sq(Y)*X ^ Y == 0   with Y = AffineInv(S ^ 0x63).
func verifySBoxLayerDegree2(x, s *[16]byte) bool {
	var acc byte
	for j := 0; j < 16; j++ {
		xj := x[j]
		yj := gf256AffineInv(s[j])
		c1 := gf256Mul(gf256Sq(xj), yj) ^ xj
		c2 := gf256Mul(gf256Sq(yj), xj) ^ yj
		acc |= c1 | c2
	}
	return acc == 0
}

func verifyWitness256Ref(m, c, k1, k2 *[32]byte, w *[288]byte, rc *[10][16]byte) bool {
	var x0, x1 [16]byte
	for i := 0; i < 16; i++ {
		x0[i] = m[i] ^ k1[i]
		x1[i] = m[16+i] ^ k1[16+i]
	}
	for r := 0; r < 10; r++ {
		var aNext, bNext [16]byte
		if r < 9 {
			copy(aNext[:], w[32*r:32*r+16])
			copy(bNext[:], w[32*r+16:32*r+32])
		} else {
			// Round 9 (odd round): A_next_9 = (C ^ K2)[16:32], B_next_9 = (C ^ K2)[0:16]
			for i := 0; i < 16; i++ {
				aNext[i] = c[16+i] ^ k2[16+i]
				bNext[i] = c[i] ^ k2[i]
			}
		}
		var aCur, bCur [16]byte
		if r%2 == 0 {
			aCur, bCur = x0, x1
		} else {
			aCur, bCur = x1, x0
		}

		// Layer 1: X1 = aCur, S1 = InvShiftRows(aNext)
		s1 := aesInvShiftRows(&aNext)
		if !verifySBoxLayerDegree2(&aCur, &s1) {
			return false
		}

		// Layer 2: X2 = MixColumns(aNext) ^ rc[r], S2 = InvShiftRows(InvMixColumns(bCur ^ bNext))
		x2 := aesMixColumns(&aNext)
		var t [16]byte
		for i := 0; i < 16; i++ {
			x2[i] ^= rc[r][i]
			t[i] = bCur[i] ^ bNext[i]
		}
		imc := aesInvMixColumns(&t)
		s2 := aesInvShiftRows(&imc)
		if !verifySBoxLayerDegree2(&x2, &s2) {
			return false
		}

		if r%2 == 0 {
			x0, x1 = aNext, bNext
		} else {
			x1, x0 = aNext, bNext
		}
	}
	return true
}

func extractWitnessEM2Ref(m, k1, k2 *[32]byte) (c [32]byte, w [576]byte) {
	var zero [32]byte
	uP1, wP1 := extractWitness256Ref(m, k1, &zero, &rcP1)
	copy(w[0:288], wP1[:])
	var vP2, k12 [32]byte
	for i := 0; i < 32; i++ {
		vP2[i] = uP1[i] ^ k2[i]
		k12[i] = k1[i] ^ k2[i]
	}
	c, wP2 := extractWitness256Ref(&vP2, &zero, &k12, &rcP2)
	copy(w[288:576], wP2[:])
	return c, w
}

func verifyWitnessEM2Ref(m, c, k1, k2 *[32]byte, w *[576]byte) bool {
	// Recompute U_P1 from Round 8 state in w[256:288] + Round 9 forward, OR verify P1 against U_P1:
	var x0, x1, zero [16]byte
	copy(x0[:], w[256:272])
	copy(x1[:], w[272:288])
	aNext9 := x1
	areion.AES128FinalRound(&aNext9, &zero)
	u9 := x1
	areion.AES128Round(&u9, &rcP1[9])
	bNext9 := u9
	areion.AES128Round(&bNext9, &x0)
	var uP1, vP2, zero32, k12 [32]byte
	copy(uP1[0:16], bNext9[:])
	copy(uP1[16:32], aNext9[:])
	for i := 0; i < 32; i++ {
		vP2[i] = uP1[i] ^ k2[i]
		k12[i] = k1[i] ^ k2[i]
	}
	var w1, w2 [288]byte
	copy(w1[:], w[0:288])
	copy(w2[:], w[288:576])
	return verifyWitness256Ref(m, &uP1, k1, &zero32, &w1, &rcP1) &&
		verifyWitness256Ref(&vP2, c, &zero32, &k12, &w2, &rcP2)
}

func runWitnessCheck(quick bool) {
	nTrials := 100000
	if quick {
		nTrials = 10000
	}
	rng := rand.New(rand.NewPCG(0x2885B08, 0xFAE57256))

	p1Pass := 0
	p2Pass := 0
	em2Pass := 0

	for t := 0; t < nTrials; t++ {
		var m, k1, k2 [32]byte
		for i := 0; i < 32; i++ {
			m[i] = byte(rng.Uint32())
			k1[i] = byte(rng.Uint32())
			k2[i] = byte(rng.Uint32())
		}
		var key64 [64]byte
		copy(key64[0:32], k1[:])
		copy(key64[32:64], k2[:])

		// 1. P1 witness extraction & verification
		c1, w1 := extractWitness256Ref(&m, &k1, &k2, &rcP1)
		expC1 := areion.EMEncrypt256(&key64, &m)
		if c1 == expC1 && verifyWitness256Ref(&m, &c1, &k1, &k2, &w1, &rcP1) {
			p1Pass++
		}

		// 2. P2 witness extraction & verification
		c2, w2 := extractWitness256Ref(&m, &k1, &k2, &rcP2)
		var stP2 [32]byte
		for i := 0; i < 32; i++ {
			stP2[i] = m[i] ^ k1[i]
		}
		areion.Permute256P2(&stP2)
		for i := 0; i < 32; i++ {
			stP2[i] ^= k2[i]
		}
		if c2 == stP2 && verifyWitness256Ref(&m, &c2, &k1, &k2, &w2, &rcP2) {
			p2Pass++
		}

		// 3. EM2 witness extraction & verification
		cEM2, wEM2 := extractWitnessEM2Ref(&m, &k1, &k2)
		expCEM2 := areion.EM2Encrypt256(&key64, &m)
		if cEM2 == expCEM2 && verifyWitnessEM2Ref(&m, &cEM2, &k1, &k2, &wEM2) {
			em2Pass++
		}
	}

	// Exhaustive single-bit corruption across all 2304 witness bits, 256 C bits, 256 M bits, 256 K1 bits
	nExhaust := 20
	if quick {
		nExhaust = 5
	}
	wBitRejects := 0
	wBitTotal := nExhaust * 2304
	r8BitRejects := 0
	r8BitTotal := nExhaust * 256
	cBitRejects := 0
	cBitTotal := nExhaust * 256
	kBitRejects := 0
	kBitTotal := nExhaust * 256

	for e := 0; e < nExhaust; e++ {
		var m, k1, k2 [32]byte
		for i := 0; i < 32; i++ {
			m[i] = byte(rng.Uint32())
			k1[i] = byte(rng.Uint32())
			k2[i] = byte(rng.Uint32())
		}
		c, w := extractWitness256Ref(&m, &k1, &k2, &rcP1)

		for bit := 0; bit < 2304; bit++ {
			wBad := w
			wBad[bit/8] ^= 1 << (bit % 8)
			if !verifyWitness256Ref(&m, &c, &k1, &k2, &wBad, &rcP1) {
				wBitRejects++
				if bit >= 2048 {
					r8BitRejects++
				}
			}
		}
		for bit := 0; bit < 256; bit++ {
			cBad := c
			cBad[bit/8] ^= 1 << (bit % 8)
			if !verifyWitness256Ref(&m, &cBad, &k1, &k2, &w, &rcP1) {
				cBitRejects++
			}
			kBad := k1
			kBad[bit/8] ^= 1 << (bit % 8)
			if !verifyWitness256Ref(&m, &c, &kBad, &k2, &w, &rcP1) {
				kBitRejects++
			}
		}
	}

	// Random multi-bit witness corruptions
	randRejects := 0
	for t := 0; t < nTrials; t++ {
		var m, k1, k2 [32]byte
		for i := 0; i < 32; i++ {
			m[i] = byte(rng.Uint32())
			k1[i] = byte(rng.Uint32())
			k2[i] = byte(rng.Uint32())
		}
		c, w := extractWitness256Ref(&m, &k1, &k2, &rcP1)
		nFlips := 1 + rng.IntN(8)
		for f := 0; f < nFlips; f++ {
			idx := rng.IntN(288)
			delta := byte(1 + rng.IntN(255))
			w[idx] ^= delta
		}
		if !verifyWitness256Ref(&m, &c, &k1, &k2, &w, &rcP1) {
			randRejects++
		}
	}

	fmt.Println("=== Go Empirical Witness & Round 9 Free-S-Box Verification ===")
	fmt.Printf("Random P1 witness extractions & degree-2 checks:  %d / %d PASS\n", p1Pass, nTrials)
	fmt.Printf("Random P2 witness extractions & degree-2 checks:  %d / %d PASS\n", p2Pass, nTrials)
	fmt.Printf("Random EM2 witness extractions & degree-2 checks: %d / %d PASS\n", em2Pass, nTrials)
	fmt.Printf("Exhaustive 1-bit witness corruptions rejected:    %d / %d (100.0%%)\n", wBitRejects, wBitTotal)
	fmt.Printf("Round 8->9 boundary 1-bit corruptions rejected:   %d / %d (100.0%%)\n", r8BitRejects, r8BitTotal)
	fmt.Printf("Final output C 1-bit corruptions rejected (R9):   %d / %d (100.0%%)\n", cBitRejects, cBitTotal)
	fmt.Printf("Secret key K1 1-bit corruptions rejected:         %d / %d (100.0%%)\n", kBitRejects, kBitTotal)
	fmt.Printf("Random multi-bit witness corruptions rejected:    %d / %d (100.0%%)\n", randRejects, nTrials)

	if p1Pass != nTrials || p2Pass != nTrials || em2Pass != nTrials ||
		wBitRejects != wBitTotal || r8BitRejects != r8BitTotal ||
		cBitRejects != cBitTotal || kBitRejects != kBitTotal || randRejects != nTrials {
		panic("witness verification check failed")
	}
}
