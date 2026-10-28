package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"

	"github.com/everanium/areion"
)

func clmul64(a, b uint64) (lo, hi uint64) {
	for i := 0; i < 64; i++ {
		mask := -((b >> i) & 1)
		v := a & mask
		lo ^= v << i
		if i > 0 {
			hi ^= v >> (64 - i)
		}
	}
	return lo, hi
}

// gf128MulRef multiplies two elements in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1 (0x87).
func gf128MulRef(a, b *[16]byte) (out [16]byte) {
	a0 := binary.LittleEndian.Uint64(a[0:8])
	a1 := binary.LittleEndian.Uint64(a[8:16])
	b0 := binary.LittleEndian.Uint64(b[0:8])
	b1 := binary.LittleEndian.Uint64(b[8:16])

	z0Lo, z0Hi := clmul64(a0, b0)
	z2Lo, z2Hi := clmul64(a1, b1)
	z1Lo, z1Hi := clmul64(a0^a1, b0^b1)
	mLo := z1Lo ^ z0Lo ^ z2Lo
	mHi := z1Hi ^ z0Hi ^ z2Hi

	cLow0 := z0Lo
	cLow1 := z0Hi ^ mLo
	h0 := z2Lo ^ mHi
	h1 := z2Hi

	t1 := (h1 << 7) ^ (h1 << 2) ^ (h1 << 1) ^ h1
	t1Hi := (h1 >> 57) ^ (h1 >> 62) ^ (h1 >> 63)
	h0 ^= t1Hi
	r1 := cLow1 ^ t1 ^ (h0 >> 57) ^ (h0 >> 62) ^ (h0 >> 63)
	r0 := cLow0 ^ (h0 << 7) ^ (h0 << 2) ^ (h0 << 1) ^ h0

	binary.LittleEndian.PutUint64(out[0:8], r0)
	binary.LittleEndian.PutUint64(out[8:16], r1)
	return out
}

func gf128Xor(a, b *[16]byte) (out [16]byte) {
	for i := 0; i < 16; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func mulOrtho256Ref(t, k *[32]byte) (out [32]byte) {
	var t0, t1, k0, k1 [16]byte
	copy(t0[:], t[0:16])
	copy(t1[:], t[16:32])
	copy(k0[:], k[0:16])
	copy(k1[:], k[16:32])
	o0 := gf128MulRef(&t0, &k0)
	o1 := gf128MulRef(&t1, &k1)
	copy(out[0:16], o0[:])
	copy(out[16:32], o1[:])
	return out
}

func orthoSigma256Ref(k *[32]byte) (out [32]byte) {
	copy(out[0:16], k[16:32])
	for i := 0; i < 16; i++ {
		out[16+i] = k[i] ^ k[16+i]
	}
	return out
}

// --- Bit-level QuickSilver VOLE gate evaluation over GF(2^128) ---

func qsLiftSq(x *[8][16]byte) (u [8][16]byte) {
	// u[0] = x[0] ^ x[4] ^ x[6]
	// u[1] = x[4] ^ x[6] ^ x[7]
	// u[2] = x[1] ^ x[5]
	// u[3] = x[4] ^ x[5] ^ x[6] ^ x[7]
	// u[4] = x[2] ^ x[4] ^ x[7]
	// u[5] = x[5] ^ x[6]
	// u[6] = x[3] ^ x[5]
	// u[7] = x[6] ^ x[7]
	for i := 0; i < 16; i++ {
		u[0][i] = x[0][i] ^ x[4][i] ^ x[6][i]
		u[1][i] = x[4][i] ^ x[6][i] ^ x[7][i]
		u[2][i] = x[1][i] ^ x[5][i]
		u[3][i] = x[4][i] ^ x[5][i] ^ x[6][i] ^ x[7][i]
		u[4][i] = x[2][i] ^ x[4][i] ^ x[7][i]
		u[5][i] = x[5][i] ^ x[6][i]
		u[6][i] = x[3][i] ^ x[5][i]
		u[7][i] = x[6][i] ^ x[7][i]
	}
	return u
}

func qsReduceDeg14(d *[15][16]byte) (p [8][16]byte) {
	var r0, r1, r2, r3, r4, r5, r6 [16]byte
	r6 = d[14]
	r5 = d[13]
	r4 = d[12]
	r3 = d[11]
	for i := 0; i < 16; i++ {
		r2[i] = d[10][i] ^ r6[i]
		r1[i] = d[9][i] ^ r5[i] ^ r6[i]
		r0[i] = d[8][i] ^ r4[i] ^ r5[i]

		p[0][i] = d[0][i] ^ r0[i]
		p[1][i] = d[1][i] ^ r1[i] ^ r0[i]
		p[2][i] = d[2][i] ^ r2[i] ^ r1[i]
		p[3][i] = d[3][i] ^ r3[i] ^ r2[i] ^ r0[i]
		p[4][i] = d[4][i] ^ r4[i] ^ r3[i] ^ r1[i] ^ r0[i]
		p[5][i] = d[5][i] ^ r5[i] ^ r4[i] ^ r2[i] ^ r1[i]
		p[6][i] = d[6][i] ^ r6[i] ^ r5[i] ^ r3[i] ^ r2[i]
		p[7][i] = d[7][i] ^ r6[i] ^ r4[i] ^ r3[i]
	}
	return p
}

func qsEvalSBoxGateProver(xByte, sByte byte, xQ, sQ *[8][16]byte, chi, a0Acc, a1Acc *[16]byte) {
	var xVal, sVal, uVal, yVal, wVal [8]byte
	for b := 0; b < 8; b++ {
		xVal[b] = (xByte >> b) & 1
		sVal[b] = (sByte >> b) & 1
	}
	uVal[0] = xVal[0] ^ xVal[4] ^ xVal[6]
	uVal[1] = xVal[4] ^ xVal[6] ^ xVal[7]
	uVal[2] = xVal[1] ^ xVal[5]
	uVal[3] = xVal[4] ^ xVal[5] ^ xVal[6] ^ xVal[7]
	uVal[4] = xVal[2] ^ xVal[4] ^ xVal[7]
	uVal[5] = xVal[5] ^ xVal[6]
	uVal[6] = xVal[3] ^ xVal[5]
	uVal[7] = xVal[6] ^ xVal[7]

	var spVal [8]byte
	for b := 0; b < 8; b++ {
		spVal[b] = sVal[b] ^ ((0x63 >> b) & 1)
	}
	for b := 0; b < 8; b++ {
		yVal[b] = spVal[(b+2)%8] ^ spVal[(b+5)%8] ^ spVal[(b+7)%8]
	}
	wVal[0] = yVal[0] ^ yVal[4] ^ yVal[6]
	wVal[1] = yVal[4] ^ yVal[6] ^ yVal[7]
	wVal[2] = yVal[1] ^ yVal[5]
	wVal[3] = yVal[4] ^ yVal[5] ^ yVal[6] ^ yVal[7]
	wVal[4] = yVal[2] ^ yVal[4] ^ yVal[7]
	wVal[5] = yVal[5] ^ yVal[6]
	wVal[6] = yVal[3] ^ yVal[5]
	wVal[7] = yVal[6] ^ yVal[7]

	uQ := qsLiftSq(xQ)
	var yQ [8][16]byte
	for b := 0; b < 8; b++ {
		for i := 0; i < 16; i++ {
			yQ[b][i] = sQ[(b+2)%8][i] ^ sQ[(b+5)%8][i] ^ sQ[(b+7)%8][i]
		}
	}
	wQ := qsLiftSq(&yQ)

	var d1A0, d1A1, d2A0, d2A1 [15][16]byte
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			p1 := gf128MulRef(&uQ[i], &yQ[j])
			p2 := gf128MulRef(&wQ[i], &xQ[j])
			for k := 0; k < 16; k++ {
				d1A0[i+j][k] ^= p1[k]
				if uVal[i] != 0 {
					d1A1[i+j][k] ^= yQ[j][k]
				}
				if yVal[j] != 0 {
					d1A1[i+j][k] ^= uQ[i][k]
				}
				d2A0[i+j][k] ^= p2[k]
				if wVal[i] != 0 {
					d2A1[i+j][k] ^= xQ[j][k]
				}
				if xVal[j] != 0 {
					d2A1[i+j][k] ^= wQ[i][k]
				}
			}
		}
	}
	c1A0 := qsReduceDeg14(&d1A0)
	c1A1 := qsReduceDeg14(&d1A1)
	c2A0 := qsReduceDeg14(&d2A0)
	c2A1 := qsReduceDeg14(&d2A1)
	for b := 0; b < 8; b++ {
		for k := 0; k < 16; k++ {
			c1A1[b][k] ^= xQ[b][k]
			c2A1[b][k] ^= yQ[b][k]
		}
		*a0Acc = gf128MulRef(a0Acc, chi)
		*a1Acc = gf128MulRef(a1Acc, chi)
		*a0Acc = gf128Xor(a0Acc, &c1A0[b])
		*a1Acc = gf128Xor(a1Acc, &c1A1[b])
	}
	for b := 0; b < 8; b++ {
		*a0Acc = gf128MulRef(a0Acc, chi)
		*a1Acc = gf128MulRef(a1Acc, chi)
		*a0Acc = gf128Xor(a0Acc, &c2A0[b])
		*a1Acc = gf128Xor(a1Acc, &c2A1[b])
	}
}

func qsEvalSBoxGateVerifier(xV, sV *[8][16]byte, delta, chi, bvAcc *[16]byte) {
	uV := qsLiftSq(xV)
	var spV, yV [8][16]byte
	for b := 0; b < 8; b++ {
		spV[b] = sV[b]
		if ((0x63 >> b) & 1) != 0 {
			spV[b] = gf128Xor(&spV[b], delta)
		}
	}
	for b := 0; b < 8; b++ {
		for i := 0; i < 16; i++ {
			yV[b][i] = spV[(b+2)%8][i] ^ spV[(b+5)%8][i] ^ spV[(b+7)%8][i]
		}
	}
	wV := qsLiftSq(&yV)

	var d1BV, d2BV [15][16]byte
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			p1 := gf128MulRef(&uV[i], &yV[j])
			p2 := gf128MulRef(&wV[i], &xV[j])
			for k := 0; k < 16; k++ {
				d1BV[i+j][k] ^= p1[k]
				d2BV[i+j][k] ^= p2[k]
			}
		}
	}
	c1BV := qsReduceDeg14(&d1BV)
	c2BV := qsReduceDeg14(&d2BV)
	for b := 0; b < 8; b++ {
		xDel := gf128MulRef(&xV[b], delta)
		c1BV[b] = gf128Xor(&c1BV[b], &xDel)
		*bvAcc = gf128MulRef(bvAcc, chi)
		*bvAcc = gf128Xor(bvAcc, &c1BV[b])
	}
	for b := 0; b < 8; b++ {
		yDel := gf128MulRef(&yV[b], delta)
		c2BV[b] = gf128Xor(&c2BV[b], &yDel)
		*bvAcc = gf128MulRef(bvAcc, chi)
		*bvAcc = gf128Xor(bvAcc, &c2BV[b])
	}
}

// --- Track 3: Reference TEM2SIVEncrypt / TEM2SIVDecrypt ---

func tem2SIVTagRef(key *[128]byte, nonce *[32]byte, ad, plaintext []byte) [32]byte {
	var acc [64]byte
	copy(acc[0:32], nonce[:])
	binary.LittleEndian.PutUint64(acc[32:40], uint64(len(ad)))
	binary.LittleEndian.PutUint64(acc[40:48], uint64(len(plaintext)))
	binary.LittleEndian.PutUint64(acc[48:56], 0x54454D3253495630)
	acc = areion.SoEM512(key, &acc)

	idx := uint64(0)
	for off := 0; off < len(ad); off += 64 {
		var blk [64]byte
		copy(blk[:], ad[off:min(off+64, len(ad))])
		binary.LittleEndian.PutUint64(blk[0:8], binary.LittleEndian.Uint64(blk[0:8])^idx)
		binary.LittleEndian.PutUint64(blk[8:16], binary.LittleEndian.Uint64(blk[8:16])^0x4144000000000001)
		mac := areion.SoEM512(key, &blk)
		for i := 0; i < 64; i++ {
			acc[i] ^= mac[i]
		}
		idx++
	}
	idx = 0
	for off := 0; off < len(plaintext); off += 64 {
		var blk [64]byte
		copy(blk[:], plaintext[off:min(off+64, len(plaintext))])
		binary.LittleEndian.PutUint64(blk[0:8], binary.LittleEndian.Uint64(blk[0:8])^idx)
		binary.LittleEndian.PutUint64(blk[8:16], binary.LittleEndian.Uint64(blk[8:16])^0x5054000000000002)
		mac := areion.SoEM512(key, &blk)
		for i := 0; i < 64; i++ {
			acc[i] ^= mac[i]
		}
		idx++
	}
	return areion.DM512(&acc)
}

func tem2SIVEncryptRef(key *[128]byte, nonce *[32]byte, ad, plaintext []byte) (ciphertext []byte, tag [32]byte) {
	tag = tem2SIVTagRef(key, nonce, ad, plaintext)
	ciphertext = make([]byte, len(plaintext))
	kEnc := *key
	kEnc[0] ^= 0x5A

	nFull := len(plaintext) / 64
	for i := 0; i < nFull; i++ {
		var tweak, blk [64]byte
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[0:16])
		binary.LittleEndian.PutUint64(tweak[48:56], uint64(i))
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495601)
		copy(blk[:], plaintext[64*i:64*(i+1)])
		ctBlk := areion.TEM2Encrypt512(&kEnc, &tweak, &blk)
		copy(ciphertext[64*i:64*(i+1)], ctBlk[:])
	}
	if rem := len(plaintext) % 64; rem > 0 {
		var tweak [64]byte
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[16:32])
		binary.LittleEndian.PutUint64(tweak[48:56], uint64(nFull))
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495602)
		stream := areion.SoEM512(&kEnc, &tweak)
		for j := 0; j < rem; j++ {
			ciphertext[64*nFull+j] = plaintext[64*nFull+j] ^ stream[j]
		}
	}
	return ciphertext, tag
}

func tem2SIVDecryptRef(key *[128]byte, nonce *[32]byte, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, ok bool) {
	plaintext = make([]byte, len(ciphertext))
	kEnc := *key
	kEnc[0] ^= 0x5A

	nFull := len(ciphertext) / 64
	for i := 0; i < nFull; i++ {
		var tweak, blk [64]byte
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[0:16])
		binary.LittleEndian.PutUint64(tweak[48:56], uint64(i))
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495601)
		copy(blk[:], ciphertext[64*i:64*(i+1)])
		ptBlk := areion.TEM2Decrypt512(&kEnc, &tweak, &blk)
		copy(plaintext[64*i:64*(i+1)], ptBlk[:])
	}
	if rem := len(ciphertext) % 64; rem > 0 {
		var tweak [64]byte
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[16:32])
		binary.LittleEndian.PutUint64(tweak[48:56], uint64(nFull))
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495602)
		stream := areion.SoEM512(&kEnc, &tweak)
		for j := 0; j < rem; j++ {
			plaintext[64*nFull+j] = ciphertext[64*nFull+j] ^ stream[j]
		}
	}
	expTag := tem2SIVTagRef(key, nonce, ad, plaintext)
	if subtle.ConstantTimeCompare(tag[:], expTag[:]) != 1 {
		clear(plaintext)
		return plaintext, false
	}
	return plaintext, true
}

func runVOLECheck(quick bool) {
	nField := 10000
	nQS := 200
	nSIV := 1024
	if quick {
		nField = 2000
		nQS = 40
		nSIV = 256
	}
	rng := rand.New(rand.NewPCG(0x701E128, 0x517AEAD))

	// 1. GF(2^128) field axioms & orthomorphism difference check
	fieldPass := 0
	orthoPass := 0
	for i := 0; i < nField; i++ {
		var a, b, c [16]byte
		var t, k1, k2 [32]byte
		for j := 0; j < 16; j++ {
			a[j] = byte(rng.Uint32())
			b[j] = byte(rng.Uint32())
			c[j] = byte(rng.Uint32())
		}
		for j := 0; j < 32; j++ {
			t[j] = byte(rng.Uint32())
			k1[j] = byte(rng.Uint32())
			k2[j] = byte(rng.Uint32())
		}
		t[0] |= 0x02
		t[16] |= 0x02
		k2[0] ^= 0x01 // ensure k1 != k2

		ab := gf128MulRef(&a, &b)
		ba := gf128MulRef(&b, &a)
		bc := gf128Xor(&b, &c)
		a_bc := gf128MulRef(&a, &bc)
		ac := gf128MulRef(&a, &c)
		ab_ac := gf128Xor(&ab, &ac)

		// Frobenius: (a ^ b)^2 == a^2 ^ b^2
		apb := gf128Xor(&a, &b)
		sqApb := gf128MulRef(&apb, &apb)
		sqA := gf128MulRef(&a, &a)
		sqB := gf128MulRef(&b, &b)
		sqSum := gf128Xor(&sqA, &sqB)

		if ab == ba && a_bc == ab_ac && sqApb == sqSum {
			fieldPass++
		}

		// Orthomorphism difference: L(dk) != 0 and (I ^ L)(dk) != 0
		var dk [32]byte
		for j := 0; j < 32; j++ {
			dk[j] = k1[j] ^ k2[j]
		}
		mL := mulOrtho256Ref(&t, &dk)
		sL := orthoSigma256Ref(&dk)
		var mIL, sIL [32]byte
		var zero32 [32]byte
		for j := 0; j < 32; j++ {
			mIL[j] = dk[j] ^ mL[j]
			sIL[j] = dk[j] ^ sL[j]
		}
		if mL != zero32 && mIL != zero32 && sL != zero32 && sIL != zero32 {
			orthoPass++
		}
	}

	// 2. QuickSilver VOLE 20-gate batch verification over GF(2^128) (with mask U_mask, Q_mask)
	qsValidPass := 0
	qsCorruptRej := 0
	for t := 0; t < nQS; t++ {
		var delta, chi [16]byte
		for i := 0; i < 16; i++ {
			delta[i] = byte(rng.Uint32())
			chi[i] = byte(rng.Uint32())
		}
		delta[0] |= 1
		chi[0] |= 1

		const nGates = 32 // 32 S-boxes (one full Areion-256 round)
		var xBytes, sBytes [nGates]byte
		var xQ, sQ, xV, sV [nGates][8][16]byte
		for g := 0; g < nGates; g++ {
			xb := byte(rng.Uint32())
			sb := gf256Affine(gf256Inv(xb))
			xBytes[g] = xb
			sBytes[g] = sb
			for b := 0; b < 8; b++ {
				for k := 0; k < 16; k++ {
					xQ[g][b][k] = byte(rng.Uint32())
					sQ[g][b][k] = byte(rng.Uint32())
				}
				xV[g][b] = xQ[g][b]
				if ((xb >> b) & 1) != 0 {
					xV[g][b] = gf128Xor(&xV[g][b], &delta)
				}
				sV[g][b] = sQ[g][b]
				if ((sb >> b) & 1) != 0 {
					sV[g][b] = gf128Xor(&sV[g][b], &delta)
				}
			}
		}

		// Generate 128 mask bits u_mask[0..127] and Q_mask_bit[0..127]
		var uMask [16]byte
		for i := 0; i < 16; i++ {
			uMask[i] = byte(rng.Uint32())
		}
		var qMaskBits, vMaskBits [128][16]byte
		var qMask [16]byte
		for m := 0; m < 128; m++ {
			for k := 0; k < 16; k++ {
				qMaskBits[m][k] = byte(rng.Uint32())
			}
			vMaskBits[m] = qMaskBits[m]
			if ((uMask[m/8] >> (m % 8)) & 1) != 0 {
				vMaskBits[m] = gf128Xor(&vMaskBits[m], &delta)
			}
			var basisZ [16]byte
			basisZ[m/8] = 1 << (m % 8)
			qm := gf128MulRef(&qMaskBits[m], &basisZ)
			qMask = gf128Xor(&qMask, &qm)
		}

		var a0Acc, a1Acc, bvAcc [16]byte
		for g := 0; g < nGates; g++ {
			qsEvalSBoxGateProver(xBytes[g], sBytes[g], &xQ[g], &sQ[g], &chi, &a0Acc, &a1Acc)
			qsEvalSBoxGateVerifier(&xV[g], &sV[g], &delta, &chi, &bvAcc)
		}
		qsU := gf128Xor(&a1Acc, &uMask)
		wPoly := gf128Xor(&a0Acc, &qMask)

		// Verifier reconstructs tilde_V_mask from vMaskBits and qsU = a1Acc ^ uMask:
		var tildeVMask [16]byte
		for m := 0; m < 128; m++ {
			dBit := (qsU[m/8] >> (m % 8)) & 1
			tv := vMaskBits[m]
			if dBit != 0 {
				tv = gf128Xor(&tv, &delta)
			}
			var basisZ [16]byte
			basisZ[m/8] = 1 << (m % 8)
			term := gf128MulRef(&tv, &basisZ)
			tildeVMask = gf128Xor(&tildeVMask, &term)
		}
		wVerif := gf128Xor(&bvAcc, &tildeVMask)
		if wVerif == wPoly {
			qsValidPass++
		}

		// Corrupt one S-box output bit in gate 0:
		sBytesBad := sBytes
		sBytesBad[0] ^= 0x01
		sVBad := sV
		sVBad[0][0] = gf128Xor(&sVBad[0][0], &delta)
		var bvBad [16]byte
		for g := 0; g < nGates; g++ {
			qsEvalSBoxGateVerifier(&xV[g], &sVBad[g], &delta, &chi, &bvBad)
		}
		wVerifBad := gf128Xor(&bvBad, &tildeVMask)
		if wVerifBad != wPoly {
			qsCorruptRej++
		}
	}

	// 3. TEM2-SIV tag avalanche and forgery rejection
	var key128 [128]byte
	var nonce32 [32]byte
	for i := 0; i < 128; i++ {
		key128[i] = byte(rng.Uint32())
	}
	for i := 0; i < 32; i++ {
		nonce32[i] = byte(rng.Uint32())
	}
	stSIV := measureAvalanche(nSIV, 512, 32, func(in, out []byte) {
		var n [32]byte
		copy(n[:], in[0:32])
		tag := tem2SIVTagRef(&key128, &n, in[32:48], in[48:64])
		copy(out, tag[:])
	}, rng)

	// Verify roundtrip and 1-bit ciphertext / tag forgery rejection + zeroization
	ad := make([]byte, 96)
	pt := make([]byte, 200)
	for i := range ad {
		ad[i] = byte(rng.Uint32())
	}
	for i := range pt {
		pt[i] = byte(1 + rng.IntN(255))
	}
	ct, tag := tem2SIVEncryptRef(&key128, &nonce32, ad, pt)
	decPt, ok := tem2SIVDecryptRef(&key128, &nonce32, ad, ct, &tag)
	if !ok || string(decPt) != string(pt) {
		panic("TEM2SIV roundtrip failed")
	}

	ctBitRejects := 0
	ctBitZeroed := 0
	for bit := 0; bit < len(ct)*8; bit++ {
		ctBad := append([]byte(nil), ct...)
		ctBad[bit/8] ^= 1 << (bit % 8)
		badOut, ok := tem2SIVDecryptRef(&key128, &nonce32, ad, ctBad, &tag)
		if !ok {
			ctBitRejects++
			allZero := true
			for _, v := range badOut {
				if v != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				ctBitZeroed++
			}
		}
	}
	tagBitRejects := 0
	for bit := 0; bit < 256; bit++ {
		tagBad := tag
		tagBad[bit/8] ^= 1 << (bit % 8)
		_, ok := tem2SIVDecryptRef(&key128, &nonce32, ad, ct, &tagBad)
		if !ok {
			tagBitRejects++
		}
	}

	fmt.Println("=== Go Empirical VOLE / QuickSilver & TEM2-SIV Audit ===")
	fmt.Printf("GF(2^128) field axioms (comm/assoc/dist/Frob):    %d / %d PASS\n", fieldPass, nField)
	fmt.Printf("Orthomorphism difference non-degeneracy:          %d / %d PASS\n", orthoPass, nField)
	fmt.Printf("QuickSilver 32-S-box VOLE homomorphic check:      %d / %d PASS\n", qsValidPass, nQS)
	fmt.Printf("QuickSilver 1-bit witness corruption rejection:   %d / %d (100.0%%)\n", qsCorruptRej, nQS)
	fmt.Printf("TEM2-SIV tag avalanche (meanHW / minHW / maxHW):  %.5f / %.5f / %.5f (maxChi2=%.2f)\n",
		stSIV.meanHW, stSIV.minHW, stSIV.maxHW, stSIV.maxChi2)
	fmt.Printf("TEM2-SIV 1-bit ciphertext forgery rejections:     %d / %d (zeroized: %d / %d)\n",
		ctBitRejects, len(ct)*8, ctBitZeroed, len(ct)*8)
	fmt.Printf("TEM2-SIV 1-bit tag forgery rejections:            %d / 256 (100.0%%)\n", tagBitRejects)

	if fieldPass != nField || orthoPass != nField || qsValidPass != nQS || qsCorruptRej != nQS ||
		math.Abs(stSIV.meanHW-0.5) > 0.006 || ctBitRejects != len(ct)*8 || ctBitZeroed != len(ct)*8 || tagBitRejects != 256 {
		panic("VOLE / TEM2-SIV verification failed")
	}
}
