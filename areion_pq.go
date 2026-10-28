package areionpq

import (
	"crypto"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"runtime"

	"github.com/everanium/areion"
)

// ============================================================================
// 1. Finite-Field & Witness Primitives
// ============================================================================

// GF256Mul computes the product of a and b in the AES finite field
// GF(2^8) = GF(2)[z] / (z^8 + z^4 + z^3 + z + 1) (irreducible modulus 0x11B).
func GF256Mul(a, b byte) byte {
	var p uint16
	aa := uint16(a)
	bb := uint16(b)
	for i := 0; i < 8; i++ {
		mask := -((bb >> i) & 1)
		p ^= aa & mask
		hi := -((aa >> 7) & 1)
		aa = ((aa << 1) & 0xff) ^ (0x1b & hi)
	}
	return byte(p)
}

// GF256Sq computes a^2 in GF(2^8) modulo 0x11B.
func GF256Sq(a byte) byte {
	return GF256Mul(a, a)
}

// GF256Inv computes the multiplicative inverse a^254 in GF(2^8) modulo 0x11B
// (with 0 -> 0) in constant time.
func GF256Inv(a byte) byte {
	a2 := GF256Sq(a)
	a3 := GF256Mul(a2, a)
	a6 := GF256Sq(a3)
	a12 := GF256Sq(a6)
	a15 := GF256Mul(a12, a3)
	a30 := GF256Sq(a15)
	a60 := GF256Sq(a30)
	a120 := GF256Sq(a60)
	a240 := GF256Sq(a120)
	a252 := GF256Mul(a240, a12)
	return GF256Mul(a252, a2)
}

// GF256Affine applies the FIPS 197 forward AES affine map over GF(2) (including ^ 0x63).
// For any byte x, GF256Affine(GF256Inv(x)) equals the AES S-box S(x).
func GF256Affine(a byte) byte {
	return a ^ bits.RotateLeft8(a, 1) ^ bits.RotateLeft8(a, 2) ^ bits.RotateLeft8(a, 3) ^ bits.RotateLeft8(a, 4) ^ 0x63
}

// GF256AffineInv applies the inverse of GF256Affine (first XORing 0x63, then
// applying the inverse linear matrix over GF(2)). For any S-box output s = S(x),
// y = GF256AffineInv(s) is the GF(2^8) inverse of x.
func GF256AffineInv(s byte) byte {
	u := s ^ 0x63
	return bits.RotateLeft8(u, 1) ^ bits.RotateLeft8(u, 3) ^ bits.RotateLeft8(u, 6)
}

// GF128Mul multiplies two 128-bit elements in GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)
// using little-endian polynomial representation (0x87 reduction polynomial).
func GF128Mul(a, b *[16]byte) [16]byte {
	var out [16]byte
	dispatchGF128Mul(&out, a, b)
	return out
}

// GF128PolyMAC evaluates the Horner polynomial accumulation over GF(2^128):
// starting from acc = 0, for each index i in 0..min(len(a),len(b))-1:
//
//	acc = GF128Mul(acc, chi) ⊕ GF128Mul(a[i], b[i])
func GF128PolyMAC(a, b [][16]byte, chi *[16]byte) [16]byte {
	var acc [16]byte
	dispatchGF128PolyMACBlocks(&acc, a, b, chi)
	return acc
}

//go:noinline
func gf256FieldMulBody(out, a, b *[32]byte) {
	var a0, a1, b0, b1, ax, bx, p0, p1, pm, p1Alpha [16]byte
	copy(a0[:], a[0:16])
	copy(a1[:], a[16:32])
	copy(b0[:], b[0:16])
	copy(b1[:], b[16:32])
	xor16(&ax, &a0, &a1)
	xor16(&bx, &b0, &b1)

	dispatchGF128MulNoWipe(&p0, &a0, &b0)
	dispatchGF128MulNoWipe(&p1, &a1, &b1)
	dispatchGF128MulNoWipe(&pm, &ax, &bx)
	alpha := [16]byte{0x87}
	dispatchGF128MulNoWipe(&p1Alpha, &p1, &alpha)

	for i := 0; i < 16; i++ {
		out[i] = p0[i] ^ p1Alpha[i]
		out[16+i] = pm[i] ^ p0[i]
	}

	clear(a0[:])
	clear(a1[:])
	clear(b0[:])
	clear(b1[:])
	clear(ax[:])
	clear(bx[:])
	clear(p0[:])
	clear(p1[:])
	clear(pm[:])
	clear(p1Alpha[:])
	runtime.KeepAlive(&a0)
	runtime.KeepAlive(&a1)
	runtime.KeepAlive(&b0)
	runtime.KeepAlive(&b1)
	runtime.KeepAlive(&ax)
	runtime.KeepAlive(&bx)
	runtime.KeepAlive(&p0)
	runtime.KeepAlive(&p1)
	runtime.KeepAlive(&pm)
	runtime.KeepAlive(&p1Alpha)
}

// GF256FieldMul multiplies two 256-bit elements in the quadratic extension
// GF(2^256) = GF(2^128)[Y] / (Y^2 + Y + alpha) where alpha = x^7 + x^2 + x + 1 (0x87).
func GF256FieldMul(a, b *[32]byte) [32]byte {
	var out [32]byte
	gf256FieldMulBody(&out, a, b)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

//go:noinline
func mulOrtho256Body(out, t, k *[32]byte) {
	var t0, t1, k0, k1, out0, out1 [16]byte
	copy(t0[:], t[0:16])
	copy(t1[:], t[16:32])
	copy(k0[:], k[0:16])
	copy(k1[:], k[16:32])
	dispatchGF128MulNoWipe(&out0, &t0, &k0)
	dispatchGF128MulNoWipe(&out1, &t1, &k1)
	copy(out[0:16], out0[:])
	copy(out[16:32], out1[:])
	clear(t0[:])
	clear(t1[:])
	clear(k0[:])
	clear(k1[:])
	clear(out0[:])
	clear(out1[:])
	runtime.KeepAlive(&t0)
	runtime.KeepAlive(&t1)
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
	runtime.KeepAlive(&out0)
	runtime.KeepAlive(&out1)
}

// MulOrtho256 evaluates the 2-lane GF(2^128) public-tweak orthomorphism
// K2 = (GF128Mul(T[0:16], K[0:16]), GF128Mul(T[16:32], K[16:32])).
// When T[0:16] and T[16:32] are not in {0, 1}, K -> MulOrtho256(T, K) and
// K -> K ⊕ MulOrtho256(T, K) are both bijections on {0,1}^256.
func MulOrtho256(t, k *[32]byte) [32]byte {
	var out [32]byte
	mulOrtho256Body(&out, t, k)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

//go:noinline
func orthoSigma256Body(out, k *[32]byte) {
	var k0, k1 [16]byte
	copy(k0[:], k[0:16])
	copy(k1[:], k[16:32])
	copy(out[0:16], k1[:])
	for i := 0; i < 16; i++ {
		out[16+i] = k0[i] ^ k1[i]
	}
	clear(k0[:])
	clear(k1[:])
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
}

// OrthoSigma256 evaluates the Feistel orthomorphism sigma(KL || KR) = KR || (KL ⊕ KR)
// on a 32-byte key K. Both sigma and id ⊕ sigma are invertible linear bijections.
func OrthoSigma256(k *[32]byte) [32]byte {
	var out [32]byte
	orthoSigma256Body(&out, k)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return out
}

// ExtractWitness256 computes C = P1(M ⊕ K1) ⊕ K2 and extracts the 288-byte
// committed S-box witness w for rounds 0..8 of 10-round Areion-256 (P1).
// Round 9 requires zero witness bytes because its output is C ⊕ K2.
func ExtractWitness256(m, k1, k2 *[32]byte) (c [32]byte, w [288]byte) {
	dispatchExtractWitness256(&c, &w, m, k1, k2, &roundConstantsP1)
	return c, w
}

// ExtractWitness256P2 computes C = P2(M ⊕ K1) ⊕ K2 and extracts the 288-byte
// committed S-box witness w for rounds 0..8 of 10-round Areion-256P2 (P2).
func ExtractWitness256P2(m, k1, k2 *[32]byte) (c [32]byte, w [288]byte) {
	dispatchExtractWitness256(&c, &w, m, k1, k2, &roundConstantsP2)
	return c, w
}

// VerifyWitness256 algebraically verifies all 320 S-box degree-2 GF(2^8) equations
// across all 10 rounds of Areion-256 (P1) for C = P1(M ⊕ K1) ⊕ K2 in constant time.
func VerifyWitness256(m, c, k1, k2 *[32]byte, w *[288]byte) bool {
	return verifyWitness256Internal(m, c, k1, k2, w, &roundConstantsP1)
}

// VerifyWitness256P2 algebraically verifies all 320 S-box degree-2 GF(2^8) equations
// across all 10 rounds of Areion-256P2 (P2) for C = P2(M ⊕ K1) ⊕ K2 in constant time.
func VerifyWitness256P2(m, c, k1, k2 *[32]byte, w *[288]byte) bool {
	return verifyWitness256Internal(m, c, k1, k2, w, &roundConstantsP2)
}

//go:noinline
func extractWitnessEM2_256Body(c *[32]byte, w *[576]byte, m, k1, k2 *[32]byte) {
	var zero32, uP1, k12 [32]byte
	var wP1, wP2 [288]byte
	xor32(&k12, k1, k2)
	dispatchExtractWitness256(&uP1, &wP1, m, k1, &zero32, &roundConstantsP1)
	dispatchExtractWitness256(c, &wP2, &uP1, k2, &k12, &roundConstantsP2)
	copy(w[0:288], wP1[:])
	copy(w[288:576], wP2[:])

	clear(uP1[:])
	clear(wP1[:])
	clear(k12[:])
	clear(wP2[:])
	runtime.KeepAlive(&uP1)
	runtime.KeepAlive(&wP1)
	runtime.KeepAlive(&k12)
	runtime.KeepAlive(&wP2)
}

// ExtractWitnessEM2_256 computes C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2 and extracts
// the 576-byte witness w (288 bytes for P1 rounds 0..8 + 288 bytes for P2 rounds 0..8).
func ExtractWitnessEM2_256(m, k1, k2 *[32]byte) (c [32]byte, w [576]byte) {
	extractWitnessEM2_256Body(&c, &w, m, k1, k2)
	if !hasHardwareExtractWitness256() {
		wipeSoftwareStack()
	}
	clobberScratchGPRs()
	return c, w
}

//go:noinline
func verifyWitnessEM2_256SoftwareBody(m, c, k1, k2 *[32]byte, w *[576]byte) bool {
	var zero32, uP1, k12 [32]byte
	var x0, x1, aNext, u9, bNext [16]byte
	var q, qRC bsState
	copy(x0[:], w[256:272])
	copy(x1[:], w[272:288])

	bsPack1(&q, &x1)
	bsSubBytes(&q)
	bsShiftRows(&q)
	bsUnpack1(&q, &aNext)

	bsMixColumns(&q)
	bsPack1(&qRC, &roundConstantsP1[9])
	for k := 0; k < 8; k++ {
		q[k] ^= qRC[k]
	}
	bsSubBytes(&q)
	bsShiftRows(&q)
	bsMixColumns(&q)
	bsUnpack1(&q, &u9)
	xor16(&bNext, &x0, &u9)

	copy(uP1[0:16], bNext[:])
	copy(uP1[16:32], aNext[:])
	xor32(&k12, k1, k2)

	ok1 := verifyWitness256SoftwareBody(m, &uP1, k1, &zero32, (*[288]byte)(w[0:288]), &roundConstantsP1)
	ok2 := verifyWitness256SoftwareBody(&uP1, c, k2, &k12, (*[288]byte)(w[288:576]), &roundConstantsP2)

	clear(uP1[:])
	clear(k12[:])
	clear(x0[:])
	clear(x1[:])
	clear(aNext[:])
	clear(u9[:])
	clear(bNext[:])
	clear(q[:])
	clear(qRC[:])
	runtime.KeepAlive(&uP1)
	runtime.KeepAlive(&k12)
	runtime.KeepAlive(&x0)
	runtime.KeepAlive(&x1)
	runtime.KeepAlive(&aNext)
	runtime.KeepAlive(&u9)
	runtime.KeepAlive(&bNext)
	runtime.KeepAlive(&q)
	runtime.KeepAlive(&qRC)

	return ok1 && ok2
}

// VerifyWitnessEM2_256 algebraically verifies all 640 S-box degree-2 GF(2^8) equations
// across P1 and P2 for C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2 in constant time.
func VerifyWitnessEM2_256(m, c, k1, k2 *[32]byte, w *[576]byte) bool {
	if hasHardwareExtractWitness256() {
		var zero32, uP1, k12, cExp [32]byte
		var wP1Exp, wP2Exp [288]byte
		xor32(&k12, k1, k2)
		dispatchExtractWitness256(&uP1, &wP1Exp, m, k1, &zero32, &roundConstantsP1)
		dispatchExtractWitness256(&cExp, &wP2Exp, &uP1, k2, &k12, &roundConstantsP2)
		diff := ctDiff288((*[288]byte)(w[0:288]), &wP1Exp) |
			ctDiff288((*[288]byte)(w[288:576]), &wP2Exp) |
			ctDiff32(c, &cExp)
		clear(uP1[:])
		clear(k12[:])
		clear(cExp[:])
		clear(wP1Exp[:])
		clear(wP2Exp[:])
		runtime.KeepAlive(&uP1)
		runtime.KeepAlive(&k12)
		runtime.KeepAlive(&cExp)
		runtime.KeepAlive(&wP1Exp)
		runtime.KeepAlive(&wP2Exp)
		clobberScratchGPRs()
		return diff == 0
	}
	ok := verifyWitnessEM2_256SoftwareBody(m, c, k1, k2, w)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return ok
}

// ============================================================================
// 2. Track 3: Areion-HPKE, KDFExpand & Areion-TEM2-SIV Wide-Block AEAD
// ============================================================================

//go:noinline
func kdfExpandBody(secret, context, dst []byte) {
	if len(dst) == 0 {
		return
	}
	var dom [32]byte
	binary.LittleEndian.PutUint64(dom[0:8], uint64(len(secret)))
	binary.LittleEndian.PutUint64(dom[8:16], uint64(len(context)))
	binary.LittleEndian.PutUint64(dom[16:24], 0x415245494F4E4B44) // "AREIONKD"

	v := areion.DM256(&dom)
	var b512 [64]byte

	for off := 0; off < len(secret); off += 32 {
		clear(b512[:])
		copy(b512[0:32], v[:])
		end := off + 32
		if end > len(secret) {
			end = len(secret)
		}
		copy(b512[32:32+(end-off)], secret[off:end])
		v = areion.DM512(&b512)
	}

	v[0] ^= 0x01
	v = areion.DM256(&v)

	for off := 0; off < len(context); off += 32 {
		clear(b512[:])
		copy(b512[0:32], v[:])
		end := off + 32
		if end > len(context) {
			end = len(context)
		}
		copy(b512[32:32+(end-off)], context[off:end])
		v = areion.DM512(&b512)
	}

	var kSoEM [128]byte
	k0 := areion.DM256(&v)
	k1 := v
	areion.Permute256P2(&k1)
	xor32(&k1, &k1, &v)

	v2 := v
	v2[0] ^= 0x02
	k2 := areion.DM256(&v2)
	k3 := v2
	areion.Permute256P2(&k3)
	xor32(&k3, &k3, &v2)

	copy(kSoEM[0:32], k0[:])
	copy(kSoEM[32:64], k1[:])
	copy(kSoEM[64:96], k2[:])
	copy(kSoEM[96:128], k3[:])

	var baseIn [64]byte
	copy(baseIn[0:32], v[:])
	copy(baseIn[32:64], v2[:])

	var keys4 [4][128]byte
	for lane := 0; lane < 4; lane++ {
		keys4[lane] = kSoEM
	}

	var in4, out4 [4][64]byte
	var in64, out64 [64]byte

	blkIdx := uint64(0)
	off := 0
	for off+256 <= len(dst) {
		for lane := 0; lane < 4; lane++ {
			in4[lane] = baseIn
			idx := blkIdx + uint64(lane)
			w0 := binary.LittleEndian.Uint64(in4[lane][0:8]) ^ idx
			w1 := binary.LittleEndian.Uint64(in4[lane][32:40]) ^ (idx ^ 0x5555555555555555)
			binary.LittleEndian.PutUint64(in4[lane][0:8], w0)
			binary.LittleEndian.PutUint64(in4[lane][32:40], w1)
		}
		out4 = areion.SoEM512x4(&keys4, &in4)
		for lane := 0; lane < 4; lane++ {
			copy(dst[off+64*lane:off+64*(lane+1)], out4[lane][:])
		}
		blkIdx += 4
		off += 256
	}

	for off < len(dst) {
		in64 = baseIn
		w0 := binary.LittleEndian.Uint64(in64[0:8]) ^ blkIdx
		w1 := binary.LittleEndian.Uint64(in64[32:40]) ^ (blkIdx ^ 0x5555555555555555)
		binary.LittleEndian.PutUint64(in64[0:8], w0)
		binary.LittleEndian.PutUint64(in64[32:40], w1)
		out64 = areion.SoEM512(&kSoEM, &in64)
		rem := len(dst) - off
		if rem > 64 {
			rem = 64
		}
		copy(dst[off:off+rem], out64[:rem])
		blkIdx++
		off += rem
	}

	clear(dom[:])
	clear(v[:])
	clear(v2[:])
	clear(b512[:])
	clear(k0[:])
	clear(k1[:])
	clear(k2[:])
	clear(k3[:])
	clear(kSoEM[:])
	clear(baseIn[:])
	clear(keys4[:])
	clear(in4[:])
	clear(out4[:])
	clear(in64[:])
	clear(out64[:])
	runtime.KeepAlive(&dom)
	runtime.KeepAlive(&v)
	runtime.KeepAlive(&v2)
	runtime.KeepAlive(&b512)
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
	runtime.KeepAlive(&k2)
	runtime.KeepAlive(&k3)
	runtime.KeepAlive(&kSoEM)
	runtime.KeepAlive(&baseIn)
	runtime.KeepAlive(&keys4)
	runtime.KeepAlive(&in4)
	runtime.KeepAlive(&out4)
	runtime.KeepAlive(&in64)
	runtime.KeepAlive(&out64)
}

// KDFExpand absorbs secret and context via a DM512 sponge and expands
// arbitrary-length pseudorandom key material into dst using SoEM512x4.
func KDFExpand(secret, context, dst []byte) {
	kdfExpandBody(secret, context, dst)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func tem2SIVComputeTag(key *[128]byte, nonce *[32]byte, ad, plaintext []byte) [32]byte {
	var acc [64]byte
	copy(acc[0:32], nonce[:])
	binary.LittleEndian.PutUint64(acc[32:40], uint64(len(ad)))
	binary.LittleEndian.PutUint64(acc[40:48], uint64(len(plaintext)))
	binary.LittleEndian.PutUint64(acc[48:56], 0x54454D3253495630) // "TEM2SIV0"
	acc = areion.SoEM512(key, &acc)

	var keys4 [4][128]byte
	for lane := 0; lane < 4; lane++ {
		keys4[lane] = *key
	}
	var in4, mac4 [4][64]byte
	var inBlk, macBlk [64]byte

	absorb := func(data []byte, dom uint64) {
		idx := uint64(0)
		off := 0
		for off+256 <= len(data) {
			for lane := 0; lane < 4; lane++ {
				copy(in4[lane][:], data[off+64*lane:off+64*(lane+1)])
				w0 := binary.LittleEndian.Uint64(in4[lane][0:8]) ^ (idx + uint64(lane))
				w1 := binary.LittleEndian.Uint64(in4[lane][8:16]) ^ dom
				binary.LittleEndian.PutUint64(in4[lane][0:8], w0)
				binary.LittleEndian.PutUint64(in4[lane][8:16], w1)
			}
			mac4 = areion.SoEM512x4(&keys4, &in4)
			for lane := 0; lane < 4; lane++ {
				for j := 0; j < 64; j += 8 {
					v := binary.LittleEndian.Uint64(acc[j:j+8]) ^ binary.LittleEndian.Uint64(mac4[lane][j:j+8])
					binary.LittleEndian.PutUint64(acc[j:j+8], v)
				}
			}
			idx += 4
			off += 256
		}
		for off < len(data) {
			clear(inBlk[:])
			rem := len(data) - off
			if rem > 64 {
				rem = 64
			}
			copy(inBlk[:rem], data[off:off+rem])
			w0 := binary.LittleEndian.Uint64(inBlk[0:8]) ^ idx
			w1 := binary.LittleEndian.Uint64(inBlk[8:16]) ^ dom
			binary.LittleEndian.PutUint64(inBlk[0:8], w0)
			binary.LittleEndian.PutUint64(inBlk[8:16], w1)
			macBlk = areion.SoEM512(key, &inBlk)
			for j := 0; j < 64; j += 8 {
				v := binary.LittleEndian.Uint64(acc[j:j+8]) ^ binary.LittleEndian.Uint64(macBlk[j:j+8])
				binary.LittleEndian.PutUint64(acc[j:j+8], v)
			}
			idx++
			off += rem
		}
	}

	absorb(ad, 0x4144000000000001)
	absorb(plaintext, 0x5054000000000002)
	tag := areion.DM512(&acc)

	clear(acc[:])
	clear(keys4[:])
	clear(in4[:])
	clear(mac4[:])
	clear(inBlk[:])
	clear(macBlk[:])
	runtime.KeepAlive(&acc)
	runtime.KeepAlive(&keys4)
	runtime.KeepAlive(&in4)
	runtime.KeepAlive(&mac4)
	runtime.KeepAlive(&inBlk)
	runtime.KeepAlive(&macBlk)
	return tag
}

//go:noinline
func tem2SIVEncryptInPlaceBody(tagOut *[32]byte, key *[128]byte, nonce *[32]byte, ad, dst, plaintext []byte) {
	tag := tem2SIVComputeTag(key, nonce, ad, plaintext)
	*tagOut = tag
	if len(plaintext) == 0 {
		return
	}

	kEnc := *key
	kEnc[0] ^= 0x5A
	var keys4 [4][128]byte
	for lane := 0; lane < 4; lane++ {
		keys4[lane] = kEnc
	}
	var tweaks4, msgs4, ct4 [4][64]byte
	var tweak, msg, ct [64]byte

	blkIdx := uint64(0)
	off := 0
	for off+256 <= len(plaintext) {
		for lane := 0; lane < 4; lane++ {
			copy(tweaks4[lane][0:32], tag[:])
			copy(tweaks4[lane][32:48], nonce[0:16])
			binary.LittleEndian.PutUint64(tweaks4[lane][48:56], blkIdx+uint64(lane))
			binary.LittleEndian.PutUint64(tweaks4[lane][56:64], 0x54454D3253495601)
			copy(msgs4[lane][:], plaintext[off+64*lane:off+64*(lane+1)])
		}
		ct4 = areion.TEM2Encrypt512x4(&keys4, &tweaks4, &msgs4)
		for lane := 0; lane < 4; lane++ {
			copy(dst[off+64*lane:off+64*(lane+1)], ct4[lane][:])
		}
		blkIdx += 4
		off += 256
	}

	for off+64 <= len(plaintext) {
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[0:16])
		binary.LittleEndian.PutUint64(tweak[48:56], blkIdx)
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495601)
		copy(msg[:], plaintext[off:off+64])
		ct = areion.TEM2Encrypt512(&kEnc, &tweak, &msg)
		copy(dst[off:off+64], ct[:])
		blkIdx++
		off += 64
	}

	if rem := len(plaintext) - off; rem > 0 {
		var tTail [64]byte
		copy(tTail[0:32], tag[:])
		copy(tTail[32:48], nonce[16:32])
		binary.LittleEndian.PutUint64(tTail[48:56], blkIdx)
		binary.LittleEndian.PutUint64(tTail[56:64], 0x54454D3253495602)
		stream := areion.SoEM512(&kEnc, &tTail)
		for i := 0; i < rem; i++ {
			dst[off+i] = plaintext[off+i] ^ stream[i]
		}
		clear(tTail[:])
		clear(stream[:])
		runtime.KeepAlive(&tTail)
		runtime.KeepAlive(&stream)
	}

	clear(kEnc[:])
	clear(keys4[:])
	clear(tweaks4[:])
	clear(msgs4[:])
	clear(ct4[:])
	clear(tweak[:])
	clear(msg[:])
	clear(ct[:])
	runtime.KeepAlive(&kEnc)
	runtime.KeepAlive(&keys4)
	runtime.KeepAlive(&tweaks4)
	runtime.KeepAlive(&msgs4)
	runtime.KeepAlive(&ct4)
	runtime.KeepAlive(&tweak)
	runtime.KeepAlive(&msg)
	runtime.KeepAlive(&ct)
}

// TEM2SIVEncryptInPlace encrypts plaintext into dst (which must have length >= len(plaintext)
// and may alias plaintext) under a 128-byte key and 32-byte nonce, returning the 32-byte SIV tag.
func TEM2SIVEncryptInPlace(key *[128]byte, nonce *[32]byte, ad, dst, plaintext []byte) (tag [32]byte) {
	tem2SIVEncryptInPlaceBody(&tag, key, nonce, ad, dst, plaintext)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return tag
}

//go:noinline
func tem2SIVDecryptInPlaceBody(key *[128]byte, nonce *[32]byte, ad, dst, ciphertext []byte, tag *[32]byte) bool {
	kEnc := *key
	kEnc[0] ^= 0x5A
	var keys4 [4][128]byte
	for lane := 0; lane < 4; lane++ {
		keys4[lane] = kEnc
	}
	var tweaks4, cts4, pt4 [4][64]byte
	var tweak, ct, pt [64]byte

	blkIdx := uint64(0)
	off := 0
	for off+256 <= len(ciphertext) {
		for lane := 0; lane < 4; lane++ {
			copy(tweaks4[lane][0:32], tag[:])
			copy(tweaks4[lane][32:48], nonce[0:16])
			binary.LittleEndian.PutUint64(tweaks4[lane][48:56], blkIdx+uint64(lane))
			binary.LittleEndian.PutUint64(tweaks4[lane][56:64], 0x54454D3253495601)
			copy(cts4[lane][:], ciphertext[off+64*lane:off+64*(lane+1)])
		}
		pt4 = areion.TEM2Decrypt512x4(&keys4, &tweaks4, &cts4)
		for lane := 0; lane < 4; lane++ {
			copy(dst[off+64*lane:off+64*(lane+1)], pt4[lane][:])
		}
		blkIdx += 4
		off += 256
	}

	for off+64 <= len(ciphertext) {
		copy(tweak[0:32], tag[:])
		copy(tweak[32:48], nonce[0:16])
		binary.LittleEndian.PutUint64(tweak[48:56], blkIdx)
		binary.LittleEndian.PutUint64(tweak[56:64], 0x54454D3253495601)
		copy(ct[:], ciphertext[off:off+64])
		pt = areion.TEM2Decrypt512(&kEnc, &tweak, &ct)
		copy(dst[off:off+64], pt[:])
		blkIdx++
		off += 64
	}

	if rem := len(ciphertext) - off; rem > 0 {
		var tTail [64]byte
		copy(tTail[0:32], tag[:])
		copy(tTail[32:48], nonce[16:32])
		binary.LittleEndian.PutUint64(tTail[48:56], blkIdx)
		binary.LittleEndian.PutUint64(tTail[56:64], 0x54454D3253495602)
		stream := areion.SoEM512(&kEnc, &tTail)
		for i := 0; i < rem; i++ {
			dst[off+i] = ciphertext[off+i] ^ stream[i]
		}
		clear(tTail[:])
		clear(stream[:])
		runtime.KeepAlive(&tTail)
		runtime.KeepAlive(&stream)
	}

	expectedTag := tem2SIVComputeTag(key, nonce, ad, dst[:len(ciphertext)])
	ok := subtle.ConstantTimeCompare(expectedTag[:], tag[:]) == 1
	if !ok {
		Zeroize(dst[:len(ciphertext)])
	}

	clear(kEnc[:])
	clear(keys4[:])
	clear(tweaks4[:])
	clear(cts4[:])
	clear(pt4[:])
	clear(tweak[:])
	clear(ct[:])
	clear(pt[:])
	clear(expectedTag[:])
	runtime.KeepAlive(&kEnc)
	runtime.KeepAlive(&keys4)
	runtime.KeepAlive(&tweaks4)
	runtime.KeepAlive(&cts4)
	runtime.KeepAlive(&pt4)
	runtime.KeepAlive(&tweak)
	runtime.KeepAlive(&ct)
	runtime.KeepAlive(&pt)
	runtime.KeepAlive(&expectedTag)
	return ok
}

// TEM2SIVDecryptInPlace decrypts ciphertext into dst (which must have length >= len(ciphertext)
// and may alias ciphertext) and verifies tag in constant time. On authentication failure,
// dst[0:len(ciphertext)] is zeroized and false is returned.
func TEM2SIVDecryptInPlace(key *[128]byte, nonce *[32]byte, ad, dst, ciphertext []byte, tag *[32]byte) bool {
	ok := tem2SIVDecryptInPlaceBody(key, nonce, ad, dst, ciphertext, tag)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return ok
}

// TEM2SIVEncrypt encrypts plaintext using the wide-block Areion-TEM2-SIV AEAD.
func TEM2SIVEncrypt(key *[128]byte, nonce *[32]byte, ad, plaintext []byte) (ciphertext []byte, tag [32]byte) {
	ciphertext = make([]byte, len(plaintext))
	tag = TEM2SIVEncryptInPlace(key, nonce, ad, ciphertext, plaintext)
	return ciphertext, tag
}

// TEM2SIVDecrypt decrypts and authenticates ciphertext using Areion-TEM2-SIV.
func TEM2SIVDecrypt(key *[128]byte, nonce *[32]byte, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, ok bool) {
	plaintext = make([]byte, len(ciphertext))
	if !TEM2SIVDecryptInPlace(key, nonce, ad, plaintext, ciphertext, tag) {
		return nil, false
	}
	return plaintext, true
}

// HPKEDeriveKeys derives a 128-byte TEM2-SIV DEM key and 32-byte base nonce
// from a 32-byte KEM shared secret and application info string.
func HPKEDeriveKeys(sharedSecret *[32]byte, info []byte) (demKey [128]byte, baseNonce [32]byte) {
	var buf [160]byte
	KDFExpand(sharedSecret[:], info, buf[:])
	copy(demKey[:], buf[0:128])
	copy(baseNonce[:], buf[128:160])
	clear(buf[:])
	runtime.KeepAlive(&buf)
	return demKey, baseNonce
}

// HPKESealDet deterministically seals plaintext under sharedSecret, info, and sequence number seq.
func HPKESealDet(sharedSecret *[32]byte, info []byte, seq uint64, ad, plaintext []byte) (ciphertext []byte, tag [32]byte) {
	demKey, nonce := HPKEDeriveKeys(sharedSecret, info)
	w0 := binary.LittleEndian.Uint64(nonce[0:8]) ^ seq
	binary.LittleEndian.PutUint64(nonce[0:8], w0)
	ciphertext, tag = TEM2SIVEncrypt(&demKey, &nonce, ad, plaintext)
	clear(demKey[:])
	clear(nonce[:])
	runtime.KeepAlive(&demKey)
	runtime.KeepAlive(&nonce)
	return ciphertext, tag
}

// HPKEOpenDet opens and authenticates a ciphertext produced by HPKESealDet.
func HPKEOpenDet(sharedSecret *[32]byte, info []byte, seq uint64, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, ok bool) {
	demKey, nonce := HPKEDeriveKeys(sharedSecret, info)
	w0 := binary.LittleEndian.Uint64(nonce[0:8]) ^ seq
	binary.LittleEndian.PutUint64(nonce[0:8], w0)
	plaintext, ok = TEM2SIVDecrypt(&demKey, &nonce, ad, ciphertext, tag)
	clear(demKey[:])
	clear(nonce[:])
	runtime.KeepAlive(&demKey)
	runtime.KeepAlive(&nonce)
	return plaintext, ok
}

// HPKESealMLKEM768 encapsulates an ephemeral shared secret to an ML-KEM-768
// encapsulation key and seals plaintext with Areion-TEM2-SIV.
func HPKESealMLKEM768(encapKeyBytes, info, ad, plaintext []byte) (kemCiphertext, ciphertext []byte, tag [32]byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(encapKeyBytes)
	if err != nil {
		return nil, nil, tag, err
	}
	sharedSecret, kemCT := ek.Encapsulate()
	var ss [32]byte
	copy(ss[:], sharedSecret)
	Zeroize(sharedSecret)
	ciphertext, tag = HPKESealDet(&ss, info, 0, ad, plaintext)
	clear(ss[:])
	runtime.KeepAlive(&ss)
	return kemCT, ciphertext, tag, nil
}

// HPKEOpenMLKEM768 decapsulates kemCiphertext using an ML-KEM-768 decapsulation
// key and opens ciphertext with Areion-TEM2-SIV.
func HPKEOpenMLKEM768(decapKey *mlkem.DecapsulationKey768, kemCiphertext, info, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, err error) {
	if decapKey == nil {
		return nil, errors.New("areionpq: nil ML-KEM-768 decapsulation key")
	}
	sharedSecret, err := decapKey.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, err
	}
	var ss [32]byte
	copy(ss[:], sharedSecret)
	Zeroize(sharedSecret)
	pt, ok := HPKEOpenDet(&ss, info, 0, ad, ciphertext, tag)
	clear(ss[:])
	runtime.KeepAlive(&ss)
	if !ok {
		return nil, errors.New("areionpq: HPKE TEM2-SIV authentication failed")
	}
	return pt, nil
}

// ============================================================================
// 3. Track 2: SLH-DSA-Areion (NIST FIPS 205 Stateless Hash-Based Signatures)
// ============================================================================

const (
	slhAdrsWOTSHash  uint32 = 0
	slhAdrsWOTSPK    uint32 = 1
	slhAdrsTree      uint32 = 2
	slhAdrsFORSTree  uint32 = 3
	slhAdrsFORSRoots uint32 = 4
	slhAdrsWOTSPRF   uint32 = 5
	slhAdrsFORSPRF   uint32 = 6
)

func slhSetLayerAddress(adrs *[32]byte, layer uint32) {
	binary.BigEndian.PutUint32(adrs[0:4], layer)
}

func slhSetTreeAddress(adrs *[32]byte, tree uint64) {
	clear(adrs[4:8])
	binary.BigEndian.PutUint64(adrs[8:16], tree)
}

func slhSetTypeAndClear(adrs *[32]byte, typ uint32) {
	binary.BigEndian.PutUint32(adrs[16:20], typ)
	clear(adrs[20:32])
}

func slhSetKeyPairAddress(adrs *[32]byte, kp uint32) {
	binary.BigEndian.PutUint32(adrs[20:24], kp)
}

func slhGetKeyPairAddress(adrs *[32]byte) uint32 {
	return binary.BigEndian.Uint32(adrs[20:24])
}

func slhSetChainAddress(adrs *[32]byte, chain uint32) {
	binary.BigEndian.PutUint32(adrs[24:28], chain)
}

func slhSetTreeHeight(adrs *[32]byte, h uint32) {
	binary.BigEndian.PutUint32(adrs[24:28], h)
}

func slhSetHashAddress(adrs *[32]byte, hash uint32) {
	binary.BigEndian.PutUint32(adrs[28:32], hash)
}

func slhSetTreeIndex(adrs *[32]byte, idx uint32) {
	binary.BigEndian.PutUint32(adrs[28:32], idx)
}

//go:noinline
func slhExpandSeed128Body(kPub, kSK *[64]byte, pkSeed, skSeed *[16]byte) {
	var p32, s32 [32]byte
	if pkSeed != nil {
		copy(p32[0:16], pkSeed[:])
		copy(p32[16:32], pkSeed[:])
	}
	if skSeed != nil {
		copy(s32[0:16], skSeed[:])
		copy(s32[16:32], skSeed[:])
		slhExpandSeed256Body(kPub, kSK, &p32, &s32)
	} else {
		slhExpandSeed256Body(kPub, kSK, &p32, nil)
	}
	clear(p32[:])
	clear(s32[:])
	runtime.KeepAlive(&p32)
	runtime.KeepAlive(&s32)
}

// SLHExpandSeed128 expands 16-byte PK.seed and SK.seed into 64-byte K_pub and K_sk.
func SLHExpandSeed128(pkSeed, skSeed *[16]byte) (kPub, kSK [64]byte) {
	slhExpandSeed128Body(&kPub, &kSK, pkSeed, skSeed)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return kPub, kSK
}

//go:noinline
func slhExpandSeed256Body(kPub, kSK *[64]byte, pkSeed, skSeed *[32]byte) {
	var p [32]byte
	if pkSeed != nil {
		p = *pkSeed
	}
	kPub1 := areion.DM256(&p)
	kPub2 := p
	areion.Permute256P2(&kPub2)
	xor32(&kPub2, &kPub2, &p)
	if kPub != nil {
		copy(kPub[0:32], kPub1[:])
		copy(kPub[32:64], kPub2[:])
	}

	if kSK != nil && skSeed != nil {
		s := *skSeed
		var ksk1, ksk2 [32]byte
		xor32(&ksk1, &s, &kPub1)
		areion.Permute256(&ksk1)
		xor32(&ksk1, &ksk1, &s)

		xor32(&ksk2, &s, &kPub2)
		areion.Permute256P2(&ksk2)
		xor32(&ksk2, &ksk2, &s)

		copy(kSK[0:32], ksk1[:])
		copy(kSK[32:64], ksk2[:])
		clear(s[:])
		clear(ksk1[:])
		clear(ksk2[:])
		runtime.KeepAlive(&s)
		runtime.KeepAlive(&ksk1)
		runtime.KeepAlive(&ksk2)
	}
	clear(p[:])
	clear(kPub1[:])
	clear(kPub2[:])
	runtime.KeepAlive(&p)
	runtime.KeepAlive(&kPub1)
	runtime.KeepAlive(&kPub2)
}

// SLHExpandSeed256 expands 32-byte PK.seed and SK.seed into 64-byte K_pub and K_sk.
func SLHExpandSeed256(pkSeed, skSeed *[32]byte) (kPub, kSK [64]byte) {
	slhExpandSeed256Body(&kPub, &kSK, pkSeed, skSeed)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return kPub, kSK
}

// SLHCompactADRS extracts the 16 active bytes of a 32-byte FIPS 205 ADRS structure.
func SLHCompactADRS(adrs *[32]byte) [16]byte {
	var c [16]byte
	c[0] = adrs[3]
	copy(c[1:9], adrs[8:16])
	c[9] = adrs[19]
	copy(c[10:12], adrs[22:24])
	c[12] = adrs[27]
	copy(c[13:16], adrs[29:32])
	return c
}

// SLHPRF128 evaluates PRF(K_sk, ADRS) -> 16 bytes for SLH-DSA-Areion-128{f,s}.
func SLHPRF128(kSK *[64]byte, adrs *[32]byte) [16]byte {
	y := areion.SoEM256(kSK, adrs)
	var out [16]byte
	copy(out[:], y[0:16])
	clear(y[:])
	runtime.KeepAlive(&y)
	return out
}

// SLHPRF256 evaluates PRF(K_sk, ADRS) -> 32 bytes for SLH-DSA-Areion-256{f,s}.
func SLHPRF256(kSK *[64]byte, adrs *[32]byte) [32]byte {
	return areion.SoEM256(kSK, adrs)
}

// SLHPRF256x4 evaluates PRF(K_sk, ADRS) on four 32-byte addresses in parallel.
func SLHPRF256x4(kSK *[64]byte, adrs *[4][32]byte) [4][32]byte {
	keys := [4][64]byte{*kSK, *kSK, *kSK, *kSK}
	out := areion.SoEM256x4(&keys, adrs)
	clear(keys[:])
	runtime.KeepAlive(&keys)
	return out
}

func slhF128Core(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1 *[16]byte) [16]byte {
	var b [64]byte
	copy(b[0:16], pkSeed[:])
	copy(b[16:48], adrs[:])
	copy(b[48:64], m1[:])
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(b[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[i:i+8])
		binary.LittleEndian.PutUint64(b[i:i+8], v)
	}
	d := areion.DM512(&b)
	var out [16]byte
	copy(out[:], d[0:16])
	return out
}

// SLHF128 evaluates the tweakable hash F(K_pub, ADRS, M_1) -> 16 bytes for n = 16.
func SLHF128(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1 *[16]byte) [16]byte {
	return slhF128Core(pkSeed, kPub, adrs, m1)
}

func slhF256Core(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	var b [64]byte
	for i := 0; i < 32; i += 8 {
		v0 := binary.LittleEndian.Uint64(adrs[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[i:i+8])
		v1 := binary.LittleEndian.Uint64(m1[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[32+i:32+i+8])
		binary.LittleEndian.PutUint64(b[i:i+8], v0)
		binary.LittleEndian.PutUint64(b[32+i:32+i+8], v1)
	}
	return areion.DM512(&b)
}

// SLHF256 evaluates the tweakable hash F(K_pub, ADRS, M_1) -> 32 bytes for n = 32 (Profile I DM512-Clamped).
func SLHF256(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	return slhF256Core(kPub, adrs, m1)
}

func slhFTEM256Core(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	enc := areion.TEMEncrypt256(kPub, m1, adrs)
	var out [32]byte
	xor32(&out, &enc, m1)
	return out
}

// SLHFTEM256 evaluates the tweakable hash F(K_pub, ADRS, M_1) -> 32 bytes for TEM-256f (Profile II TEM-MiddleTweak).
func SLHFTEM256(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	return slhFTEM256Core(kPub, adrs, m1)
}

func slhH128Core(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1, m2 *[16]byte) [16]byte {
	c := SLHCompactADRS(adrs)
	var b [64]byte
	copy(b[0:16], pkSeed[:])
	copy(b[16:32], c[:])
	copy(b[32:48], m1[:])
	copy(b[48:64], m2[:])
	for i := 0; i < 64; i += 8 {
		v := binary.LittleEndian.Uint64(b[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[i:i+8])
		binary.LittleEndian.PutUint64(b[i:i+8], v)
	}
	d := areion.DM512(&b)
	var out [16]byte
	copy(out[:], d[0:16])
	return out
}

// SLHH128 evaluates the 2-to-1 tweakable hash H(K_pub, ADRS, M_1 || M_2) -> 16 bytes for n = 16.
func SLHH128(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1, m2 *[16]byte) [16]byte {
	return slhH128Core(pkSeed, kPub, adrs, m1, m2)
}

func slhH256Core(kPub *[64]byte, adrs *[32]byte, m1, m2 *[32]byte) [32]byte {
	var b1, b2 [64]byte
	for i := 0; i < 32; i += 8 {
		v0 := binary.LittleEndian.Uint64(adrs[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[i:i+8])
		v1 := binary.LittleEndian.Uint64(m1[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[32+i:32+i+8])
		binary.LittleEndian.PutUint64(b1[i:i+8], v0)
		binary.LittleEndian.PutUint64(b1[32+i:32+i+8], v1)
	}
	v1 := areion.DM512(&b1)
	for i := 0; i < 32; i += 8 {
		w0 := binary.LittleEndian.Uint64(v1[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[i:i+8])
		w1 := binary.LittleEndian.Uint64(m2[i:i+8]) ^ binary.LittleEndian.Uint64(adrs[i:i+8]) ^ binary.LittleEndian.Uint64(kPub[32+i:32+i+8])
		binary.LittleEndian.PutUint64(b2[i:i+8], w0)
		binary.LittleEndian.PutUint64(b2[32+i:32+i+8], w1)
	}
	b2[0] ^= 0x02
	return areion.DM512(&b2)
}

// SLHH256 evaluates the 2-to-1 tweakable hash H(K_pub, ADRS, M_1 || M_2) -> 32 bytes for n = 32.
func SLHH256(kPub *[64]byte, adrs *[32]byte, m1, m2 *[32]byte) [32]byte {
	return slhH256Core(kPub, adrs, m1, m2)
}

// SLHTl128 evaluates the multi-block tweakable hash T_l(K_pub, ADRS, blocks) -> 16 bytes.
func SLHTl128(kPub *[64]byte, adrs *[32]byte, blocks [][16]byte) [16]byte {
	var b [64]byte
	var m0, mi [32]byte
	if len(blocks) > 0 {
		copy(m0[0:16], blocks[0][:])
	}
	for j := 0; j < 32; j += 8 {
		v0 := binary.LittleEndian.Uint64(adrs[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[j:j+8])
		v1 := binary.LittleEndian.Uint64(m0[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[32+j:32+j+8])
		binary.LittleEndian.PutUint64(b[j:j+8], v0)
		binary.LittleEndian.PutUint64(b[32+j:32+j+8], v1)
	}
	v := areion.DM512(&b)
	for idx := 1; idx < len(blocks); idx++ {
		copy(mi[0:16], blocks[idx][:])
		for j := 0; j < 32; j += 8 {
			w0 := binary.LittleEndian.Uint64(v[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[j:j+8])
			w1 := binary.LittleEndian.Uint64(mi[j:j+8]) ^ binary.LittleEndian.Uint64(adrs[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[32+j:32+j+8])
			binary.LittleEndian.PutUint64(b[j:j+8], w0)
			binary.LittleEndian.PutUint64(b[32+j:32+j+8], w1)
		}
		wDom := binary.LittleEndian.Uint64(b[0:8]) ^ uint64(idx+1)
		binary.LittleEndian.PutUint64(b[0:8], wDom)
		v = areion.DM512(&b)
	}
	var out [16]byte
	copy(out[:], v[0:16])
	clear(b[:])
	clear(m0[:])
	clear(mi[:])
	clear(v[:])
	runtime.KeepAlive(&b)
	runtime.KeepAlive(&m0)
	runtime.KeepAlive(&mi)
	runtime.KeepAlive(&v)
	return out
}

// SLHTl256 evaluates the multi-block tweakable hash T_l(K_pub, ADRS, blocks) -> 32 bytes.
func SLHTl256(kPub *[64]byte, adrs *[32]byte, blocks [][32]byte) [32]byte {
	var b [64]byte
	var m0 [32]byte
	if len(blocks) > 0 {
		m0 = blocks[0]
	}
	for j := 0; j < 32; j += 8 {
		v0 := binary.LittleEndian.Uint64(adrs[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[j:j+8])
		v1 := binary.LittleEndian.Uint64(m0[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[32+j:32+j+8])
		binary.LittleEndian.PutUint64(b[j:j+8], v0)
		binary.LittleEndian.PutUint64(b[32+j:32+j+8], v1)
	}
	v := areion.DM512(&b)
	for idx := 1; idx < len(blocks); idx++ {
		mi := &blocks[idx]
		for j := 0; j < 32; j += 8 {
			w0 := binary.LittleEndian.Uint64(v[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[j:j+8])
			w1 := binary.LittleEndian.Uint64(mi[j:j+8]) ^ binary.LittleEndian.Uint64(adrs[j:j+8]) ^ binary.LittleEndian.Uint64(kPub[32+j:32+j+8])
			binary.LittleEndian.PutUint64(b[j:j+8], w0)
			binary.LittleEndian.PutUint64(b[32+j:32+j+8], w1)
		}
		wDom := binary.LittleEndian.Uint64(b[0:8]) ^ uint64(idx+1)
		binary.LittleEndian.PutUint64(b[0:8], wDom)
		v = areion.DM512(&b)
	}
	clear(b[:])
	clear(m0[:])
	runtime.KeepAlive(&b)
	runtime.KeepAlive(&m0)
	return v
}

type slhParams struct {
	n      int
	h      int
	d      int
	hp     int
	a      int
	k      int
	wotsL  int
	mBytes int
	useTEM bool
}

var (
	slhParams128f    = slhParams{n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, wotsL: 35, mBytes: 34, useTEM: false}
	slhParams128s    = slhParams{n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, wotsL: 35, mBytes: 30, useTEM: false}
	slhParams256f    = slhParams{n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, wotsL: 67, mBytes: 49, useTEM: false}
	slhParams256s    = slhParams{n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, wotsL: 67, mBytes: 47, useTEM: false}
	slhParamsTEM256f = slhParams{n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, wotsL: 67, mBytes: 49, useTEM: true}
)

func slhPRFMsg(p *slhParams, skPRF, optRand []byte, msg []byte, out []byte) {
	var pPRF, oRand, xee, bj [32]byte
	if p.n == 16 {
		copy(pPRF[0:16], skPRF[0:16])
		copy(pPRF[16:32], skPRF[0:16])
		copy(oRand[0:16], optRand[0:16])
		copy(oRand[16:32], optRand[0:16])
	} else {
		copy(pPRF[:], skPRF[0:32])
		copy(oRand[:], optRand[0:32])
	}
	xor32(&xee, &pPRF, &oRand)
	v := areion.DM256(&xee)

	numBlocks := (len(msg) / 32) + 1
	var b512 [64]byte
	for blk := 0; blk < numBlocks; blk++ {
		clear(bj[:])
		off := blk * 32
		if off+32 <= len(msg) {
			copy(bj[:], msg[off:off+32])
		} else {
			rem := len(msg) - off
			if rem > 0 {
				copy(bj[:rem], msg[off:])
			}
			bj[rem] = 0x80
		}
		for i := 0; i < 32; i++ {
			b512[i] = v[i] ^ pPRF[i]
			b512[32+i] = bj[i] ^ oRand[i]
		}
		v = areion.DM512(&b512)
	}

	var kPRF [64]byte
	dmP := areion.DM256(&pPRF)
	copy(kPRF[0:32], pPRF[:])
	copy(kPRF[32:64], dmP[:])
	res := areion.SoEM256(&kPRF, &v)
	copy(out[0:p.n], res[0:p.n])

	clear(pPRF[:])
	clear(oRand[:])
	clear(xee[:])
	clear(bj[:])
	clear(v[:])
	clear(b512[:])
	clear(kPRF[:])
	clear(dmP[:])
	clear(res[:])
	runtime.KeepAlive(&pPRF)
	runtime.KeepAlive(&oRand)
	runtime.KeepAlive(&xee)
	runtime.KeepAlive(&bj)
	runtime.KeepAlive(&v)
	runtime.KeepAlive(&b512)
	runtime.KeepAlive(&kPRF)
	runtime.KeepAlive(&dmP)
	runtime.KeepAlive(&res)
}

func slhHMsg(p *slhParams, r, pkSeed, pkRoot []byte, kPub *[64]byte, msg []byte, out []byte) {
	var r32, s32, root32 [32]byte
	if p.n == 16 {
		copy(r32[0:16], r[0:16])
		copy(r32[16:32], r[0:16])
		copy(s32[0:16], pkSeed[0:16])
		copy(s32[16:32], pkSeed[0:16])
		copy(root32[0:16], pkRoot[0:16])
		copy(root32[16:32], pkRoot[0:16])
	} else {
		copy(r32[:], r[0:32])
		copy(s32[:], pkSeed[0:32])
		copy(root32[:], pkRoot[0:32])
	}

	var b512 [64]byte
	copy(b512[0:32], r32[:])
	copy(b512[32:64], s32[:])
	v := areion.DM512(&b512)

	copy(b512[0:32], v[:])
	copy(b512[32:64], root32[:])
	v = areion.DM512(&b512)

	numBlocks := (len(msg) / 32) + 1
	for blk := 0; blk < numBlocks; blk++ {
		var bj [32]byte
		off := blk * 32
		if off+32 <= len(msg) {
			copy(bj[:], msg[off:off+32])
		} else {
			rem := len(msg) - off
			if rem > 0 {
				copy(bj[:rem], msg[off:])
			}
			bj[rem] = 0x80
		}
		for i := 0; i < 32; i++ {
			b512[i] = v[i] ^ kPub[i]
			b512[32+i] = bj[i] ^ kPub[32+i]
		}
		v = areion.DM512(&b512)
	}

	vCtr := v
	vCtr[0] ^= 0x01
	var in64 [64]byte
	copy(in64[0:32], v[:])
	copy(in64[32:64], vCtr[:])
	var k128 [128]byte
	copy(k128[0:64], kPub[:])
	copy(k128[64:128], kPub[:])
	out64 := areion.SoEM512(&k128, &in64)
	copy(out[0:p.mBytes], out64[0:p.mBytes])
}

func slhBase2b(in []byte, b int, out []uint32) {
	inIdx := 0
	bitsAcc := 0
	var total uint32
	mask := (uint32(1) << b) - 1
	for i := 0; i < len(out); i++ {
		for bitsAcc < b {
			total = (total << 8) | uint32(in[inIdx])
			inIdx++
			bitsAcc += 8
		}
		bitsAcc -= b
		out[i] = (total >> bitsAcc) & mask
	}
}

func slhWOTSMsgNibbles(p *slhParams, m []byte, out []uint32) {
	var csum uint32
	for i := 0; i < p.n; i++ {
		hi := uint32(m[i] >> 4)
		lo := uint32(m[i] & 0x0f)
		out[2*i] = hi
		out[2*i+1] = lo
		csum += (15 - hi) + (15 - lo)
	}
	out[2*p.n+0] = (csum >> 8) & 0x0f
	out[2*p.n+1] = (csum >> 4) & 0x0f
	out[2*p.n+2] = csum & 0x0f
}

func slhWOTSChainSingle(p *slhParams, x *[32]byte, start, steps int, pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte) [32]byte {
	cur := *x
	adrsLocal := *adrs
	for s := start; s < start+steps; s++ {
		slhSetHashAddress(&adrsLocal, uint32(s))
		if p.n == 16 {
			var m16 [16]byte
			copy(m16[:], cur[0:16])
			res16 := slhF128Core(pkSeed, kPub, &adrsLocal, &m16)
			copy(cur[0:16], res16[:])
		} else if p.useTEM {
			cur = slhFTEM256Core(kPub, &adrsLocal, &cur)
		} else {
			cur = slhF256Core(kPub, &adrsLocal, &cur)
		}
	}
	return cur
}

func slhWOTSPKGen(p *slhParams, pkSeed *[16]byte, kPub, kSK *[64]byte, adrs *[32]byte) [32]byte {
	var tmp256 [67][32]byte
	var tmp128 [35][16]byte
	skADRS := *adrs
	slhSetTypeAndClear(&skADRS, slhAdrsWOTSPRF)
	slhSetKeyPairAddress(&skADRS, slhGetKeyPairAddress(adrs))

	chainADRS := *adrs
	var sk [32]byte
	if p.n == 32 && !p.useTEM {
		var kpub1, kpub2 [32]byte
		var adrs4, chAdrs4, sk4, out4 [4][32]byte
		keys4 := [4][64]byte{*kSK, *kSK, *kSK, *kSK}
		copy(kpub1[:], kPub[0:32])
		copy(kpub2[:], kPub[32:64])
		i := 0
		for ; i+4 <= p.wotsL; i += 4 {
			for lane := 0; lane < 4; lane++ {
				adrs4[lane] = skADRS
				slhSetChainAddress(&adrs4[lane], uint32(i+lane))
				chAdrs4[lane] = chainADRS
				slhSetChainAddress(&chAdrs4[lane], uint32(i+lane))
			}
			sk4 = areion.SoEM256x4(&keys4, &adrs4)
			slhWOTSChain256x4SoftwareBody(&out4, &sk4, &chAdrs4, &kpub1, &kpub2, 0, 15)
			for lane := 0; lane < 4; lane++ {
				tmp256[i+lane] = out4[lane]
			}
		}
		for ; i < p.wotsL; i++ {
			slhSetChainAddress(&skADRS, uint32(i))
			sk = areion.SoEM256(kSK, &skADRS)
			slhSetChainAddress(&chainADRS, uint32(i))
			tmp256[i] = slhWOTSChainSingle(p, &sk, 0, 15, pkSeed, kPub, &chainADRS)
		}
		clear(keys4[:])
		clear(sk4[:])
		clear(out4[:])
		runtime.KeepAlive(&keys4)
		runtime.KeepAlive(&sk4)
		runtime.KeepAlive(&out4)
	} else {
		for i := 0; i < p.wotsL; i++ {
			slhSetChainAddress(&skADRS, uint32(i))
			sk = areion.SoEM256(kSK, &skADRS)
			slhSetChainAddress(&chainADRS, uint32(i))
			end := slhWOTSChainSingle(p, &sk, 0, 15, pkSeed, kPub, &chainADRS)
			if p.n == 16 {
				copy(tmp128[i][:], end[0:16])
			} else {
				tmp256[i] = end
			}
		}
	}
	clear(sk[:])
	runtime.KeepAlive(&sk)

	wotspkADRS := *adrs
	slhSetTypeAndClear(&wotspkADRS, slhAdrsWOTSPK)
	slhSetKeyPairAddress(&wotspkADRS, slhGetKeyPairAddress(adrs))
	var out [32]byte
	if p.n == 16 {
		res16 := SLHTl128(kPub, &wotspkADRS, tmp128[:p.wotsL])
		copy(out[0:16], res16[:])
	} else {
		out = SLHTl256(kPub, &wotspkADRS, tmp256[:p.wotsL])
	}
	return out
}

func slhWOTSSign(p *slhParams, m []byte, pkSeed *[16]byte, kPub, kSK *[64]byte, adrs *[32]byte, sigOut []byte) {
	var msgNibbles [67]uint32
	slhWOTSMsgNibbles(p, m, msgNibbles[:p.wotsL])

	skADRS := *adrs
	slhSetTypeAndClear(&skADRS, slhAdrsWOTSPRF)
	slhSetKeyPairAddress(&skADRS, slhGetKeyPairAddress(adrs))
	chainADRS := *adrs

	var sk, node [32]byte
	var sk16 [16]byte
	for i := 0; i < p.wotsL; i++ {
		slhSetChainAddress(&skADRS, uint32(i))
		if p.n == 16 {
			sk16 = SLHPRF128(kSK, &skADRS)
			copy(sk[0:16], sk16[:])
		} else {
			sk = SLHPRF256(kSK, &skADRS)
		}
		slhSetChainAddress(&chainADRS, uint32(i))
		node = slhWOTSChainSingle(p, &sk, 0, int(msgNibbles[i]), pkSeed, kPub, &chainADRS)
		copy(sigOut[i*p.n:(i+1)*p.n], node[0:p.n])
	}
	clear(sk[:])
	clear(sk16[:])
	clear(node[:])
	runtime.KeepAlive(&sk)
	runtime.KeepAlive(&sk16)
	runtime.KeepAlive(&node)
}

func slhWOTSPKFromSig(p *slhParams, sig []byte, m []byte, pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte) [32]byte {
	var msgNibbles [67]uint32
	slhWOTSMsgNibbles(p, m, msgNibbles[:p.wotsL])
	var tmp256 [67][32]byte
	var tmp128 [35][16]byte
	chainADRS := *adrs

	for i := 0; i < p.wotsL; i++ {
		var sigNode [32]byte
		copy(sigNode[0:p.n], sig[i*p.n:(i+1)*p.n])
		slhSetChainAddress(&chainADRS, uint32(i))
		step := int(msgNibbles[i])
		end := slhWOTSChainSingle(p, &sigNode, step, 15-step, pkSeed, kPub, &chainADRS)
		if p.n == 16 {
			copy(tmp128[i][:], end[0:16])
		} else {
			tmp256[i] = end
		}
	}

	wotspkADRS := *adrs
	slhSetTypeAndClear(&wotspkADRS, slhAdrsWOTSPK)
	slhSetKeyPairAddress(&wotspkADRS, slhGetKeyPairAddress(adrs))
	var out [32]byte
	if p.n == 16 {
		res16 := SLHTl128(kPub, &wotspkADRS, tmp128[:p.wotsL])
		copy(out[0:16], res16[:])
	} else {
		out = SLHTl256(kPub, &wotspkADRS, tmp256[:p.wotsL])
	}
	return out
}

func slhTreeHash(p *slhParams, left, right *[32]byte, pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte) [32]byte {
	if p.n == 16 {
		var l16, r16 [16]byte
		copy(l16[:], left[0:16])
		copy(r16[:], right[0:16])
		h16 := slhH128Core(pkSeed, kPub, adrs, &l16, &r16)
		var out [32]byte
		copy(out[0:16], h16[:])
		return out
	}
	return slhH256Core(kPub, adrs, left, right)
}

func slhXMSSNode(p *slhParams, idx, z uint32, pkSeed *[16]byte, kPub, kSK *[64]byte, adrs *[32]byte) [32]byte {
	numLeaves := uint32(1) << z
	baseLeaf := idx * numLeaves
	var nodes [512][32]byte
	for l := uint32(0); l < numLeaves; l++ {
		leafADRS := *adrs
		slhSetTypeAndClear(&leafADRS, slhAdrsWOTSHash)
		slhSetKeyPairAddress(&leafADRS, baseLeaf+l)
		nodes[l] = slhWOTSPKGen(p, pkSeed, kPub, kSK, &leafADRS)
	}
	treeADRS := *adrs
	slhSetTypeAndClear(&treeADRS, slhAdrsTree)
	for h := uint32(1); h <= z; h++ {
		slhSetTreeHeight(&treeADRS, h)
		half := uint32(1) << (z - h)
		baseIdx := idx * half
		for i := uint32(0); i < half; i++ {
			slhSetTreeIndex(&treeADRS, baseIdx+i)
			nodes[i] = slhTreeHash(p, &nodes[2*i], &nodes[2*i+1], pkSeed, kPub, &treeADRS)
		}
	}
	return nodes[0]
}

func slhXMSSSign(p *slhParams, m *[32]byte, idx uint32, pkSeed *[16]byte, kPub, kSK *[64]byte, adrs *[32]byte, sigOut []byte) [32]byte {
	numLeaves := uint32(1) << uint32(p.hp)
	var nodes [512][32]byte
	for l := uint32(0); l < numLeaves; l++ {
		leafADRS := *adrs
		slhSetTypeAndClear(&leafADRS, slhAdrsWOTSHash)
		slhSetKeyPairAddress(&leafADRS, l)
		nodes[l] = slhWOTSPKGen(p, pkSeed, kPub, kSK, &leafADRS)
	}

	wotsADRS := *adrs
	slhSetTypeAndClear(&wotsADRS, slhAdrsWOTSHash)
	slhSetKeyPairAddress(&wotsADRS, idx)
	wotsSigBytes := p.wotsL * p.n
	slhWOTSSign(p, m[0:p.n], pkSeed, kPub, kSK, &wotsADRS, sigOut[0:wotsSigBytes])

	authOff := wotsSigBytes
	treeADRS := *adrs
	slhSetTypeAndClear(&treeADRS, slhAdrsTree)
	for h := uint32(0); h < uint32(p.hp); h++ {
		sib := (idx >> h) ^ 1
		copy(sigOut[authOff+int(h)*p.n:authOff+int(h+1)*p.n], nodes[sib][0:p.n])
		slhSetTreeHeight(&treeADRS, h+1)
		half := uint32(1) << (uint32(p.hp) - 1 - h)
		for i := uint32(0); i < half; i++ {
			slhSetTreeIndex(&treeADRS, i)
			nodes[i] = slhTreeHash(p, &nodes[2*i], &nodes[2*i+1], pkSeed, kPub, &treeADRS)
		}
	}
	return nodes[0]
}

func slhXMSSPKFromSig(p *slhParams, idx uint32, sig []byte, m *[32]byte, pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte) [32]byte {
	wotsADRS := *adrs
	slhSetTypeAndClear(&wotsADRS, slhAdrsWOTSHash)
	slhSetKeyPairAddress(&wotsADRS, idx)
	wotsSigBytes := p.wotsL * p.n
	node := slhWOTSPKFromSig(p, sig[0:wotsSigBytes], m[0:p.n], pkSeed, kPub, &wotsADRS)

	authOff := wotsSigBytes
	treeADRS := *adrs
	slhSetTypeAndClear(&treeADRS, slhAdrsTree)
	for k := uint32(0); k < uint32(p.hp); k++ {
		var authK [32]byte
		copy(authK[0:p.n], sig[authOff+int(k)*p.n:authOff+int(k+1)*p.n])
		slhSetTreeHeight(&treeADRS, k+1)
		slhSetTreeIndex(&treeADRS, idx>>(k+1))
		if ((idx >> k) & 1) == 0 {
			node = slhTreeHash(p, &node, &authK, pkSeed, kPub, &treeADRS)
		} else {
			node = slhTreeHash(p, &authK, &node, pkSeed, kPub, &treeADRS)
		}
	}
	return node
}

func slhFORSSign(p *slhParams, md []byte, pkSeed *[16]byte, kPub, kSK *[64]byte, adrs *[32]byte, sigOut []byte) [32]byte {
	var indices [35]uint32
	slhBase2b(md, p.a, indices[:p.k])

	var roots256 [35][32]byte
	var roots128 [35][16]byte
	numLeaves := uint32(1) << uint32(p.a)
	var nodesBuf [512][32]byte
	var nodes [][32]byte
	if numLeaves <= 512 {
		nodes = nodesBuf[:numLeaves]
	} else {
		nodes = make([][32]byte, numLeaves)
	}

	var sk [32]byte
	var sk16, m16 [16]byte

	for i := 0; i < p.k; i++ {
		treeOffset := uint32(i) << uint32(p.a)
		idx := indices[i]
		sigTreeOff := i * (p.a + 1) * p.n

		skADRS := *adrs
		slhSetTypeAndClear(&skADRS, slhAdrsFORSPRF)
		slhSetKeyPairAddress(&skADRS, slhGetKeyPairAddress(adrs))
		slhSetTreeHeight(&skADRS, 0)

		treeADRS := *adrs
		slhSetTypeAndClear(&treeADRS, slhAdrsFORSTree)
		slhSetKeyPairAddress(&treeADRS, slhGetKeyPairAddress(adrs))

		for l := uint32(0); l < numLeaves; l++ {
			slhSetTreeIndex(&skADRS, treeOffset+l)
			if p.n == 16 {
				sk16 = SLHPRF128(kSK, &skADRS)
				copy(sk[0:16], sk16[:])
				if l == idx {
					copy(sigOut[sigTreeOff:sigTreeOff+p.n], sk16[:])
				}
			} else {
				sk = SLHPRF256(kSK, &skADRS)
				if l == idx {
					copy(sigOut[sigTreeOff:sigTreeOff+p.n], sk[:])
				}
			}
			slhSetTreeHeight(&treeADRS, 0)
			slhSetTreeIndex(&treeADRS, treeOffset+l)
			if p.n == 16 {
				copy(m16[:], sk[0:16])
				f16 := slhF128Core(pkSeed, kPub, &treeADRS, &m16)
				copy(nodes[l][0:16], f16[:])
			} else if p.useTEM {
				nodes[l] = slhFTEM256Core(kPub, &treeADRS, &sk)
			} else {
				nodes[l] = slhF256Core(kPub, &treeADRS, &sk)
			}
		}

		authOff := sigTreeOff + p.n
		for h := uint32(0); h < uint32(p.a); h++ {
			sib := (idx >> h) ^ 1
			copy(sigOut[authOff+int(h)*p.n:authOff+int(h+1)*p.n], nodes[sib][0:p.n])
			slhSetTreeHeight(&treeADRS, h+1)
			half := uint32(1) << (uint32(p.a) - 1 - h)
			baseIdx := uint32(i) * half
			for j := uint32(0); j < half; j++ {
				slhSetTreeIndex(&treeADRS, baseIdx+j)
				nodes[j] = slhTreeHash(p, &nodes[2*j], &nodes[2*j+1], pkSeed, kPub, &treeADRS)
			}
		}
		if p.n == 16 {
			copy(roots128[i][:], nodes[0][0:16])
		} else {
			roots256[i] = nodes[0]
		}
	}
	clear(sk[:])
	clear(sk16[:])
	clear(m16[:])
	runtime.KeepAlive(&sk)
	runtime.KeepAlive(&sk16)
	runtime.KeepAlive(&m16)

	forspkADRS := *adrs
	slhSetTypeAndClear(&forspkADRS, slhAdrsFORSRoots)
	slhSetKeyPairAddress(&forspkADRS, slhGetKeyPairAddress(adrs))
	var out [32]byte
	if p.n == 16 {
		res16 := SLHTl128(kPub, &forspkADRS, roots128[:p.k])
		copy(out[0:16], res16[:])
	} else {
		out = SLHTl256(kPub, &forspkADRS, roots256[:p.k])
	}
	return out
}

func slhFORSPKFromSig(p *slhParams, sig []byte, md []byte, pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte) [32]byte {
	var indices [35]uint32
	slhBase2b(md, p.a, indices[:p.k])

	var roots256 [35][32]byte
	var roots128 [35][16]byte
	treeADRS := *adrs
	slhSetTypeAndClear(&treeADRS, slhAdrsFORSTree)
	slhSetKeyPairAddress(&treeADRS, slhGetKeyPairAddress(adrs))

	for i := 0; i < p.k; i++ {
		treeOffset := uint32(i) << uint32(p.a)
		idx := indices[i]
		sigTreeOff := i * (p.a + 1) * p.n

		var sk [32]byte
		copy(sk[0:p.n], sig[sigTreeOff:sigTreeOff+p.n])
		slhSetTreeHeight(&treeADRS, 0)
		slhSetTreeIndex(&treeADRS, treeOffset+idx)
		var node [32]byte
		if p.n == 16 {
			var m16 [16]byte
			copy(m16[:], sk[0:16])
			f16 := slhF128Core(pkSeed, kPub, &treeADRS, &m16)
			copy(node[0:16], f16[:])
		} else if p.useTEM {
			node = slhFTEM256Core(kPub, &treeADRS, &sk)
		} else {
			node = slhF256Core(kPub, &treeADRS, &sk)
		}

		authOff := sigTreeOff + p.n
		for h := uint32(0); h < uint32(p.a); h++ {
			var authH [32]byte
			copy(authH[0:p.n], sig[authOff+int(h)*p.n:authOff+int(h+1)*p.n])
			slhSetTreeHeight(&treeADRS, h+1)
			slhSetTreeIndex(&treeADRS, (treeOffset+idx)>>(h+1))
			if ((idx >> h) & 1) == 0 {
				node = slhTreeHash(p, &node, &authH, pkSeed, kPub, &treeADRS)
			} else {
				node = slhTreeHash(p, &authH, &node, pkSeed, kPub, &treeADRS)
			}
		}
		if p.n == 16 {
			copy(roots128[i][:], node[0:16])
		} else {
			roots256[i] = node
		}
	}

	forspkADRS := *adrs
	slhSetTypeAndClear(&forspkADRS, slhAdrsFORSRoots)
	slhSetKeyPairAddress(&forspkADRS, slhGetKeyPairAddress(adrs))
	var out [32]byte
	if p.n == 16 {
		res16 := SLHTl128(kPub, &forspkADRS, roots128[:p.k])
		copy(out[0:16], res16[:])
	} else {
		out = SLHTl256(kPub, &forspkADRS, roots256[:p.k])
	}
	return out
}

func slhSplitDigest(p *slhParams, digest []byte) (md []byte, idxTree uint64, idxLeaf uint32) {
	mdLen := (p.k*p.a + 7) / 8
	treeBytes := (p.h - p.hp + 7) / 8
	leafBytes := (p.hp + 7) / 8
	md = digest[0:mdLen]

	for i := 0; i < treeBytes; i++ {
		idxTree = (idxTree << 8) | uint64(digest[mdLen+i])
	}
	treeBits := p.h - p.hp
	if treeBits < 64 {
		idxTree &= (uint64(1) << treeBits) - 1
	}

	for i := 0; i < leafBytes; i++ {
		idxLeaf = (idxLeaf << 8) | uint32(digest[mdLen+treeBytes+i])
	}
	idxLeaf &= (uint32(1) << p.hp) - 1
	return md, idxTree, idxLeaf
}

//go:noinline
func slhKeygenCoreBody(p *slhParams, seed, pk, sk []byte) {
	skSeed := seed[0:p.n]
	skPRF := seed[p.n : 2*p.n]
	pkSeed := seed[2*p.n : 3*p.n]

	var pkSeed16, skSeed16 [16]byte
	var pkSeed32, skSeed32 [32]byte
	var kPub, kSK [64]byte
	if p.n == 16 {
		copy(pkSeed16[:], pkSeed)
		copy(skSeed16[:], skSeed)
		slhExpandSeed128Body(&kPub, &kSK, &pkSeed16, &skSeed16)
	} else {
		copy(pkSeed32[:], pkSeed)
		copy(skSeed32[:], skSeed)
		slhExpandSeed256Body(&kPub, &kSK, &pkSeed32, &skSeed32)
	}

	var adrs [32]byte
	slhSetLayerAddress(&adrs, uint32(p.d-1))
	root := slhXMSSNode(p, 0, uint32(p.hp), &pkSeed16, &kPub, &kSK, &adrs)

	copy(pk[0:p.n], pkSeed)
	copy(pk[p.n:2*p.n], root[0:p.n])

	copy(sk[0:p.n], skSeed)
	copy(sk[p.n:2*p.n], skPRF)
	copy(sk[2*p.n:3*p.n], pkSeed)
	copy(sk[3*p.n:4*p.n], root[0:p.n])

	clear(skSeed16[:])
	clear(skSeed32[:])
	clear(kSK[:])
	runtime.KeepAlive(&skSeed16)
	runtime.KeepAlive(&skSeed32)
	runtime.KeepAlive(&kSK)
}

func slhKeygenCore(p *slhParams, seed, pk, sk []byte) {
	slhKeygenCoreBody(p, seed, pk, sk)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func slhSignCoreBody(p *slhParams, sk, msg, optRand, sigOut []byte) {
	skSeed := sk[0:p.n]
	skPRF := sk[p.n : 2*p.n]
	pkSeed := sk[2*p.n : 3*p.n]
	pkRoot := sk[3*p.n : 4*p.n]

	var pkSeed16, skSeed16 [16]byte
	var pkSeed32, skSeed32 [32]byte
	var kPub, kSK [64]byte
	if p.n == 16 {
		copy(pkSeed16[:], pkSeed)
		copy(skSeed16[:], skSeed)
		slhExpandSeed128Body(&kPub, &kSK, &pkSeed16, &skSeed16)
	} else {
		copy(pkSeed32[:], pkSeed)
		copy(skSeed32[:], skSeed)
		slhExpandSeed256Body(&kPub, &kSK, &pkSeed32, &skSeed32)
	}

	var optLocal [32]byte
	if optRand != nil {
		copy(optLocal[0:p.n], optRand[0:p.n])
	} else {
		copy(optLocal[0:p.n], pkSeed)
	}

	r := sigOut[0:p.n]
	slhPRFMsg(p, skPRF, optLocal[0:p.n], msg, r)

	var digest [64]byte
	slhHMsg(p, r, pkSeed, pkRoot, &kPub, msg, digest[0:p.mBytes])
	md, idxTree, idxLeaf := slhSplitDigest(p, digest[0:p.mBytes])

	var adrs [32]byte
	slhSetTreeAddress(&adrs, idxTree)
	slhSetTypeAndClear(&adrs, slhAdrsFORSTree)
	slhSetKeyPairAddress(&adrs, idxLeaf)

	forsBytes := p.k * (p.a + 1) * p.n
	root := slhFORSSign(p, md, &pkSeed16, &kPub, &kSK, &adrs, sigOut[p.n:p.n+forsBytes])

	xmssBytes := (p.wotsL + p.hp) * p.n
	htOff := p.n + forsBytes
	for layer := 0; layer < p.d; layer++ {
		slhSetLayerAddress(&adrs, uint32(layer))
		slhSetTreeAddress(&adrs, idxTree)
		root = slhXMSSSign(p, &root, idxLeaf, &pkSeed16, &kPub, &kSK, &adrs, sigOut[htOff+layer*xmssBytes:htOff+(layer+1)*xmssBytes])
		idxLeaf = uint32(idxTree & ((uint64(1) << p.hp) - 1))
		idxTree >>= p.hp
	}

	clear(skSeed16[:])
	clear(skSeed32[:])
	clear(kSK[:])
	clear(optLocal[:])
	runtime.KeepAlive(&skSeed16)
	runtime.KeepAlive(&skSeed32)
	runtime.KeepAlive(&kSK)
	runtime.KeepAlive(&optLocal)
}

func slhSignCore(p *slhParams, sk, msg, optRand, sigOut []byte) {
	slhSignCoreBody(p, sk, msg, optRand, sigOut)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func slhVerifyCoreBody(p *slhParams, pk, msg, sig []byte) bool {
	pkSeed := pk[0:p.n]
	pkRoot := pk[p.n : 2*p.n]

	var pkSeed16 [16]byte
	var pkSeed32 [32]byte
	var kPub [64]byte
	if p.n == 16 {
		copy(pkSeed16[:], pkSeed)
		slhExpandSeed128Body(&kPub, nil, &pkSeed16, nil)
	} else {
		copy(pkSeed32[:], pkSeed)
		slhExpandSeed256Body(&kPub, nil, &pkSeed32, nil)
	}

	r := sig[0:p.n]
	var digest [64]byte
	slhHMsg(p, r, pkSeed, pkRoot, &kPub, msg, digest[0:p.mBytes])
	md, idxTree, idxLeaf := slhSplitDigest(p, digest[0:p.mBytes])

	var adrs [32]byte
	slhSetTreeAddress(&adrs, idxTree)
	slhSetTypeAndClear(&adrs, slhAdrsFORSTree)
	slhSetKeyPairAddress(&adrs, idxLeaf)

	forsBytes := p.k * (p.a + 1) * p.n
	node := slhFORSPKFromSig(p, sig[p.n:p.n+forsBytes], md, &pkSeed16, &kPub, &adrs)

	xmssBytes := (p.wotsL + p.hp) * p.n
	htOff := p.n + forsBytes
	for layer := 0; layer < p.d; layer++ {
		slhSetLayerAddress(&adrs, uint32(layer))
		slhSetTreeAddress(&adrs, idxTree)
		node = slhXMSSPKFromSig(p, idxLeaf, sig[htOff+layer*xmssBytes:htOff+(layer+1)*xmssBytes], &node, &pkSeed16, &kPub, &adrs)
		idxLeaf = uint32(idxTree & ((uint64(1) << p.hp) - 1))
		idxTree >>= p.hp
	}

	return subtle.ConstantTimeCompare(node[0:p.n], pkRoot) == 1
}

func slhVerifyCore(p *slhParams, pk, msg, sig []byte) bool {
	ok := slhVerifyCoreBody(p, pk, msg, sig)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return ok
}

// SLHDSAKeygen128f generates an SLH-DSA-Areion-128f keypair from a 48-byte seed.
func SLHDSAKeygen128f(seed *[48]byte) (pk [32]byte, sk [64]byte) {
	slhKeygenCore(&slhParams128f, seed[:], pk[:], sk[:])
	return pk, sk
}

// SLHDSASign128f signs msg under an SLH-DSA-Areion-128f secret key.
func SLHDSASign128f(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [17088]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	slhSignCore(&slhParams128f, sk[:], msg, opt, sig[:])
	return sig
}

// SLHDSAVerify128f verifies an SLH-DSA-Areion-128f signature.
func SLHDSAVerify128f(pk *[32]byte, msg []byte, sig *[17088]byte) bool {
	return slhVerifyCore(&slhParams128f, pk[:], msg, sig[:])
}

// SLHDSAKeygen128s generates an SLH-DSA-Areion-128s keypair from a 48-byte seed.
func SLHDSAKeygen128s(seed *[48]byte) (pk [32]byte, sk [64]byte) {
	slhKeygenCore(&slhParams128s, seed[:], pk[:], sk[:])
	return pk, sk
}

// SLHDSASign128s signs msg under an SLH-DSA-Areion-128s secret key.
func SLHDSASign128s(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [7856]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	slhSignCore(&slhParams128s, sk[:], msg, opt, sig[:])
	return sig
}

// SLHDSAVerify128s verifies an SLH-DSA-Areion-128s signature.
func SLHDSAVerify128s(pk *[32]byte, msg []byte, sig *[7856]byte) bool {
	return slhVerifyCore(&slhParams128s, pk[:], msg, sig[:])
}

// SLHDSAKeygen256f generates an SLH-DSA-Areion-256f keypair from a 96-byte seed.
func SLHDSAKeygen256f(seed *[96]byte) (pk [64]byte, sk [128]byte) {
	slhKeygenCore(&slhParams256f, seed[:], pk[:], sk[:])
	return pk, sk
}

// SLHDSASign256f signs msg under an SLH-DSA-Areion-256f secret key.
func SLHDSASign256f(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [49856]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	slhSignCore(&slhParams256f, sk[:], msg, opt, sig[:])
	return sig
}

// SLHDSAVerify256f verifies an SLH-DSA-Areion-256f signature.
func SLHDSAVerify256f(pk *[64]byte, msg []byte, sig *[49856]byte) bool {
	return slhVerifyCore(&slhParams256f, pk[:], msg, sig[:])
}

// SLHDSAKeygen256s generates an SLH-DSA-Areion-256s keypair from a 96-byte seed.
func SLHDSAKeygen256s(seed *[96]byte) (pk [64]byte, sk [128]byte) {
	slhKeygenCore(&slhParams256s, seed[:], pk[:], sk[:])
	return pk, sk
}

// SLHDSASign256s signs msg under an SLH-DSA-Areion-256s secret key.
func SLHDSASign256s(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [29792]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	slhSignCore(&slhParams256s, sk[:], msg, opt, sig[:])
	return sig
}

// SLHDSAVerify256s verifies an SLH-DSA-Areion-256s signature.
func SLHDSAVerify256s(pk *[64]byte, msg []byte, sig *[29792]byte) bool {
	return slhVerifyCore(&slhParams256s, pk[:], msg, sig[:])
}

// SLHDSATEMKeygen256f generates an SLH-DSA-Areion-TEM-256f keypair from a 96-byte seed.
func SLHDSATEMKeygen256f(seed *[96]byte) (pk [64]byte, sk [128]byte) {
	slhKeygenCore(&slhParamsTEM256f, seed[:], pk[:], sk[:])
	return pk, sk
}

// SLHDSATEMSign256f signs msg under an SLH-DSA-Areion-TEM-256f secret key.
func SLHDSATEMSign256f(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [49856]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	slhSignCore(&slhParamsTEM256f, sk[:], msg, opt, sig[:])
	return sig
}

// SLHDSATEMVerify256f verifies an SLH-DSA-Areion-TEM-256f signature.
func SLHDSATEMVerify256f(pk *[64]byte, msg []byte, sig *[49856]byte) bool {
	return slhVerifyCore(&slhParamsTEM256f, pk[:], msg, sig[:])
}

// ============================================================================
// 4. Track 1: FAEST-Areion (VOLE-in-the-Head Zero-Knowledge Signatures)
// ============================================================================

type faestParams struct {
	lambda  int
	kBytes  int
	wBytes  int
	lBytes  int
	lExt    int
	tau     int
	depths  [32]int
	isEM2   bool
	sigSize int
}

var (
	faestParams128s = faestParams{
		lambda: 16, kBytes: 16, wBytes: 288, lBytes: 304, lExt: 320, tau: 13,
		depths:  [32]int{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 8},
		isEM2:   false,
		sigSize: FAEST128sSigSize,
	}
	faestParams128f = faestParams{
		lambda: 16, kBytes: 16, wBytes: 288, lBytes: 304, lExt: 320, tau: 16,
		depths:  [32]int{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8},
		isEM2:   false,
		sigSize: FAEST128fSigSize,
	}
	faestParams256s = faestParams{
		lambda: 32, kBytes: 32, wBytes: 288, lBytes: 320, lExt: 352, tau: 26,
		depths: [32]int{
			10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
			10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
			8, 8,
		},
		isEM2:   false,
		sigSize: FAEST256sSigSize,
	}
	faestParams256f = faestParams{
		lambda: 32, kBytes: 32, wBytes: 288, lBytes: 320, lExt: 352, tau: 32,
		depths: [32]int{
			8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
			8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		},
		isEM2:   false,
		sigSize: FAEST256fSigSize,
	}
	faestParamsEM2256s = faestParams{
		lambda: 32, kBytes: 32, wBytes: 576, lBytes: 608, lExt: 640, tau: 26,
		depths: [32]int{
			10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
			10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
			8, 8,
		},
		isEM2:   true,
		sigSize: FAESTEM2256sSigSize,
	}
	faestParamsEM2256f = faestParams{
		lambda: 32, kBytes: 32, wBytes: 576, lBytes: 608, lExt: 640, tau: 32,
		depths: [32]int{
			8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
			8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
		},
		isEM2:   true,
		sigSize: FAESTEM2256fSigSize,
	}
)

func faestDeriveTM(pSeed *[32]byte) (t, m [32]byte) {
	var k128 [128]byte
	var z64 [64]byte
	copy(k128[0:32], pSeed[:])
	copy(k128[32:64], pSeed[:])
	copy(k128[64:96], pSeed[:])
	copy(k128[96:128], pSeed[:])
	tm := areion.SoEM512(&k128, &z64)
	copy(t[:], tm[0:32])
	copy(m[:], tm[32:64])
	t[0] |= 0x02
	t[16] |= 0x02
	return t, m
}

//go:noinline
func faestKeygen128CoreBody(pk *[48]byte, sk *[64]byte, seed *[32]byte) {
	var k32, pSeed, k2, state, c [32]byte
	copy(k32[0:16], seed[0:16])
	copy(k32[16:32], seed[0:16])
	copy(pSeed[0:16], seed[16:32])
	copy(pSeed[16:32], seed[16:32])

	t, m := faestDeriveTM(&pSeed)
	mulOrtho256Body(&k2, &t, &k32)
	xor32(&state, &m, &k32)
	areion.Permute256(&state)
	xor32(&c, &state, &k2)

	copy(pk[0:16], seed[16:32])
	copy(pk[16:48], c[:])

	copy(sk[0:16], seed[0:16])
	copy(sk[16:32], seed[16:32])
	copy(sk[32:64], c[:])

	clear(k32[:])
	clear(k2[:])
	clear(state[:])
	runtime.KeepAlive(&k32)
	runtime.KeepAlive(&k2)
	runtime.KeepAlive(&state)
}

func faestKeygen128Core(seed *[32]byte) (pk [48]byte, sk [64]byte) {
	faestKeygen128CoreBody(&pk, &sk, seed)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return pk, sk
}

//go:noinline
func faestKeygen256CoreBody(pk *[64]byte, sk *[96]byte, seed *[64]byte, isEM2 bool) {
	var k32, pSeed, k2, state, c [32]byte
	copy(k32[:], seed[0:32])
	copy(pSeed[:], seed[32:64])

	t, m := faestDeriveTM(&pSeed)
	if isEM2 {
		orthoSigma256Body(&k2, &k32)
		var k64 [64]byte
		copy(k64[0:32], k32[:])
		copy(k64[32:64], k2[:])
		c = areion.EM2Encrypt256(&k64, &m)
		clear(k64[:])
		runtime.KeepAlive(&k64)
	} else {
		mulOrtho256Body(&k2, &t, &k32)
		xor32(&state, &m, &k32)
		areion.Permute256(&state)
		xor32(&c, &state, &k2)
	}

	copy(pk[0:32], pSeed[:])
	copy(pk[32:64], c[:])

	copy(sk[0:32], k32[:])
	copy(sk[32:64], pSeed[:])
	copy(sk[64:96], c[:])

	clear(k32[:])
	clear(k2[:])
	clear(state[:])
	runtime.KeepAlive(&k32)
	runtime.KeepAlive(&k2)
	runtime.KeepAlive(&state)
}

func faestKeygen256Core(seed *[64]byte, isEM2 bool) (pk [64]byte, sk [96]byte) {
	faestKeygen256CoreBody(&pk, &sk, seed, isEM2)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return pk, sk
}

func faestExpandNode(lambda int, salt *[32]byte, t, lvl, idx int, s []byte, c0, c1 []byte) {
	var bNode [64]byte
	if lambda == 16 {
		copy(bNode[0:16], s[0:16])
		copy(bNode[16:32], s[0:16])
	} else {
		copy(bNode[0:32], s[0:32])
	}
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(bNode[i:i+8]) ^ binary.LittleEndian.Uint64(salt[i:i+8])
		binary.LittleEndian.PutUint64(bNode[i:i+8], v)
	}
	binary.LittleEndian.PutUint64(bNode[32:40], uint64(t))
	binary.LittleEndian.PutUint64(bNode[40:48], uint64(lvl))
	binary.LittleEndian.PutUint64(bNode[48:56], uint64(idx))
	binary.LittleEndian.PutUint64(bNode[56:64], 0x47474D4E4F444501)

	if lambda == 16 {
		h32 := areion.DM512(&bNode)
		copy(c0[0:16], h32[0:16])
		copy(c1[0:16], h32[16:32])
	} else {
		h0 := areion.DM512(&bNode)
		bNode[56] ^= 0x01
		h1 := areion.DM512(&bNode)
		copy(c0[0:32], h0[:])
		copy(c1[0:32], h1[:])
	}
}

func faestExpandLeaf(lambda, lExt int, salt *[32]byte, t, j int, sLeaf []byte, rowOut, comOut []byte) {
	var kLeaf [64]byte
	if lambda == 16 {
		copy(kLeaf[0:16], sLeaf[0:16])
		copy(kLeaf[16:32], sLeaf[0:16])
	} else {
		copy(kLeaf[0:32], sLeaf[0:32])
	}
	copy(kLeaf[32:64], salt[:])

	totalBytes := lExt
	if comOut != nil {
		totalBytes += lambda
	}
	numBlks := (totalBytes + 31) / 32
	var buf [22 * 32]byte

	var keys4 [4][64]byte
	for lane := 0; lane < 4; lane++ {
		keys4[lane] = kLeaf
	}
	var in4, out4 [4][32]byte
	var in32, out32 [32]byte

	blk := 0
	if rowOut == nil {
		blk = lExt / 32
	}
	for ; blk+4 <= numBlks; blk += 4 {
		for lane := 0; lane < 4; lane++ {
			binary.LittleEndian.PutUint64(in4[lane][0:8], uint64(t))
			binary.LittleEndian.PutUint64(in4[lane][8:16], uint64(j))
			binary.LittleEndian.PutUint64(in4[lane][16:24], uint64(blk+lane))
			binary.LittleEndian.PutUint64(in4[lane][24:32], 0x564F4C454C454146)
		}
		out4 = areion.SoEM256x4(&keys4, &in4)
		for lane := 0; lane < 4; lane++ {
			copy(buf[32*(blk+lane):32*(blk+lane+1)], out4[lane][:])
		}
	}
	for ; blk < numBlks; blk++ {
		binary.LittleEndian.PutUint64(in32[0:8], uint64(t))
		binary.LittleEndian.PutUint64(in32[8:16], uint64(j))
		binary.LittleEndian.PutUint64(in32[16:24], uint64(blk))
		binary.LittleEndian.PutUint64(in32[24:32], 0x564F4C454C454146)
		out32 = areion.SoEM256(&kLeaf, &in32)
		copy(buf[32*blk:32*(blk+1)], out32[:])
	}

	if rowOut != nil {
		copy(rowOut[0:lExt], buf[0:lExt])
	}
	if comOut != nil {
		copy(comOut[0:lambda], buf[lExt:lExt+lambda])
	}
}

type qsByteWire struct {
	val byte
	tag [8][16]byte
}

func qsXorByteWire(out, a, b *qsByteWire) {
	out.val = a.val ^ b.val
	for k := 0; k < 8; k++ {
		xor16(&out.tag[k], &a.tag[k], &b.tag[k])
	}
}

func qsAddConstByte(out, w *qsByteWire, c byte, isVerifier bool, delta *[16]byte) {
	*out = *w
	if !isVerifier {
		out.val ^= c
	} else {
		for k := 0; k < 8; k++ {
			xor16Masked(&out.tag[k], delta, -uint64((c>>k)&1))
		}
	}
}

func qsXtimeByteWire(out, w *qsByteWire) {
	var r qsByteWire
	r.val = GF256Mul(w.val, 0x02)
	r.tag[0] = w.tag[7]
	xor16(&r.tag[1], &w.tag[0], &w.tag[7])
	r.tag[2] = w.tag[1]
	xor16(&r.tag[3], &w.tag[2], &w.tag[7])
	xor16(&r.tag[4], &w.tag[3], &w.tag[7])
	r.tag[5] = w.tag[4]
	r.tag[6] = w.tag[5]
	r.tag[7] = w.tag[6]
	*out = r
}

var qsInvShiftRowsIdx = [16]int{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3}

func qsInvShiftRowsBlock(out, in *[16]qsByteWire) {
	if out == in {
		var tmp [16]qsByteWire
		for i := 0; i < 16; i++ {
			tmp[i] = in[qsInvShiftRowsIdx[i]]
		}
		*out = tmp
		return
	}
	for i := 0; i < 16; i++ {
		out[i] = in[qsInvShiftRowsIdx[i]]
	}
}

func qsMixColumnsBlock(out, in *[16]qsByteWire) {
	var t01, t23, t, s12, s30, xt01, xt12, xt23, xt30, u0, u1, u2, u3 qsByteWire
	for col := 0; col < 4; col++ {
		s0 := &in[4*col+0]
		s1 := &in[4*col+1]
		s2 := &in[4*col+2]
		s3 := &in[4*col+3]
		qsXorByteWire(&t01, s0, s1)
		qsXorByteWire(&t23, s2, s3)
		qsXorByteWire(&t, &t01, &t23)

		qsXorByteWire(&s12, s1, s2)
		qsXorByteWire(&s30, s3, s0)

		qsXtimeByteWire(&xt01, &t01)
		qsXtimeByteWire(&xt12, &s12)
		qsXtimeByteWire(&xt23, &t23)
		qsXtimeByteWire(&xt30, &s30)

		qsXorByteWire(&u0, s0, &t)
		qsXorByteWire(&u1, s1, &t)
		qsXorByteWire(&u2, s2, &t)
		qsXorByteWire(&u3, s3, &t)

		qsXorByteWire(&out[4*col+0], &u0, &xt01)
		qsXorByteWire(&out[4*col+1], &u1, &xt12)
		qsXorByteWire(&out[4*col+2], &u2, &xt23)
		qsXorByteWire(&out[4*col+3], &u3, &xt30)
	}
}

func qsInvMixColumnsBlock(out, in *[16]qsByteWire) {
	var pre [16]qsByteWire
	var s02, s13, u1, u, v1, v qsByteWire
	for col := 0; col < 4; col++ {
		s0 := &in[4*col+0]
		s1 := &in[4*col+1]
		s2 := &in[4*col+2]
		s3 := &in[4*col+3]
		qsXorByteWire(&s02, s0, s2)
		qsXorByteWire(&s13, s1, s3)
		qsXtimeByteWire(&u1, &s02)
		qsXtimeByteWire(&u, &u1)
		qsXtimeByteWire(&v1, &s13)
		qsXtimeByteWire(&v, &v1)
		qsXorByteWire(&pre[4*col+0], s0, &u)
		qsXorByteWire(&pre[4*col+1], s1, &v)
		qsXorByteWire(&pre[4*col+2], s2, &u)
		qsXorByteWire(&pre[4*col+3], s3, &v)
	}
	qsMixColumnsBlock(out, &pre)
}

func qsSqGF256Wire(u, x *qsByteWire) {
	var t46, t67, t467 [16]byte
	u.val = GF256Sq(x.val)
	// Exact reduction of x^2 modulo z^8 + z^4 + z^3 + z + 1 (0x11B):
	// z^8 = 0x1B, z^10 = 0x6C, z^12 = 0xAB, z^14 = 0x9A.
	xor16(&t46, &x.tag[4], &x.tag[6])
	xor16(&t67, &x.tag[6], &x.tag[7])
	xor16(&t467, &t46, &x.tag[7])

	// u[0] = x[0] ^ x[4] ^ x[6]
	xor16(&u.tag[0], &x.tag[0], &t46)
	// u[1] = x[4] ^ x[6] ^ x[7]
	u.tag[1] = t467
	// u[2] = x[1] ^ x[5]
	xor16(&u.tag[2], &x.tag[1], &x.tag[5])
	// u[3] = x[4] ^ x[5] ^ x[6] ^ x[7]
	xor16(&u.tag[3], &t467, &x.tag[5])
	// u[4] = x[2] ^ x[4] ^ x[7]
	xor16(&u.tag[4], &x.tag[2], &x.tag[4])
	xor16(&u.tag[4], &u.tag[4], &x.tag[7])
	// u[5] = x[5] ^ x[6]
	xor16(&u.tag[5], &x.tag[5], &x.tag[6])
	// u[6] = x[3] ^ x[5]
	xor16(&u.tag[6], &x.tag[3], &x.tag[5])
	// u[7] = x[6] ^ x[7]
	u.tag[7] = t67
}

func qsAffineInvWire(y, s *qsByteWire, isVerifier bool, delta *[16]byte) {
	var sp qsByteWire
	var t [16]byte
	qsAddConstByte(&sp, s, 0x63, isVerifier, delta)
	y.val = GF256AffineInv(s.val)
	for b := 0; b < 8; b++ {
		xor16(&t, &sp.tag[(b+2)%8], &sp.tag[(b+5)%8])
		xor16(&y.tag[b], &t, &sp.tag[(b+7)%8])
	}
}

func qsReduceGF256Tags(p *[8][16]byte, d *[15][16]byte) {
	// z^8  = 0x1B (bits 0, 1, 3, 4)
	// z^9  = 0x36 (bits 1, 2, 4, 5)
	// z^10 = 0x6C (bits 2, 3, 5, 6)
	// z^11 = 0xD8 (bits 3, 4, 6, 7)
	// z^12 = 0xAB (bits 0, 1, 3, 5, 7)
	// z^13 = 0x4D (bits 0, 2, 3, 6)
	// z^14 = 0x9A (bits 1, 3, 4, 7)
	var modMask = [7]byte{0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A}
	for i := 0; i < 8; i++ {
		p[i] = d[i]
	}
	for k := 0; k < 7; k++ {
		m := modMask[k]
		for b := 0; b < 8; b++ {
			if ((m >> b) & 1) != 0 {
				xor16(&p[b], &p[b], &d[8+k])
			}
		}
	}
}

func qsMul2(d *[3][16]byte, a, b *[2][16]byte) {
	var a01, b01 [16]byte
	dispatchGF128MulNoWipe(&d[0], &a[0], &b[0])
	dispatchGF128MulNoWipe(&d[2], &a[1], &b[1])
	xor16(&a01, &a[0], &a[1])
	xor16(&b01, &b[0], &b[1])
	dispatchGF128MulNoWipe(&d[1], &a01, &b01)
	xor16(&d[1], &d[1], &d[0])
	xor16(&d[1], &d[1], &d[2])
}

func qsMul4(d *[7][16]byte, a, b *[4][16]byte) {
	var dLo, dHi, dMid [3][16]byte
	var aMid, bMid [2][16]byte
	qsMul2(&dLo, (*[2][16]byte)(a[0:2]), (*[2][16]byte)(b[0:2]))
	qsMul2(&dHi, (*[2][16]byte)(a[2:4]), (*[2][16]byte)(b[2:4]))
	xor16(&aMid[0], &a[0], &a[2])
	xor16(&aMid[1], &a[1], &a[3])
	xor16(&bMid[0], &b[0], &b[2])
	xor16(&bMid[1], &b[1], &b[3])
	qsMul2(&dMid, &aMid, &bMid)
	for i := 0; i < 3; i++ {
		xor16(&dMid[i], &dMid[i], &dLo[i])
		xor16(&dMid[i], &dMid[i], &dHi[i])
	}
	d[0] = dLo[0]
	d[1] = dLo[1]
	xor16(&d[2], &dLo[2], &dMid[0])
	d[3] = dMid[1]
	xor16(&d[4], &dHi[0], &dMid[2])
	d[5] = dHi[1]
	d[6] = dHi[2]
}

func qsMul8(d *[15][16]byte, a, b *[8][16]byte) {
	var dLo, dHi, dMid [7][16]byte
	var aMid, bMid [4][16]byte
	qsMul4(&dLo, (*[4][16]byte)(a[0:4]), (*[4][16]byte)(b[0:4]))
	qsMul4(&dHi, (*[4][16]byte)(a[4:8]), (*[4][16]byte)(b[4:8]))
	for i := 0; i < 4; i++ {
		xor16(&aMid[i], &a[i], &a[4+i])
		xor16(&bMid[i], &b[i], &b[4+i])
	}
	qsMul4(&dMid, &aMid, &bMid)
	for i := 0; i < 7; i++ {
		xor16(&dMid[i], &dMid[i], &dLo[i])
		xor16(&dMid[i], &dMid[i], &dHi[i])
	}
	d[0] = dLo[0]
	d[1] = dLo[1]
	d[2] = dLo[2]
	d[3] = dLo[3]
	xor16(&d[4], &dLo[4], &dMid[0])
	xor16(&d[5], &dLo[5], &dMid[1])
	xor16(&d[6], &dLo[6], &dMid[2])
	d[7] = dMid[3]
	xor16(&d[8], &dHi[0], &dMid[4])
	xor16(&d[9], &dHi[1], &dMid[5])
	xor16(&d[10], &dHi[2], &dMid[6])
	d[11] = dHi[3]
	d[12] = dHi[4]
	d[13] = dHi[5]
	d[14] = dHi[6]
}

func qsEvalBilinearConstraint(a, b, c *qsByteWire, isVerifier bool, delta, chi, a1Acc, a0OrBVAcc *[16]byte) {
	// Compute degree-14 unreduced tag products:
	// On Prover: dA0[k] = XOR_{i+j=k} GF128Mul(Q(a[i]), Q(b[j])),
	//            dA1[k] = XOR_{i+j=k} (val(a[i])*Q(b[j]) ^ val(b[j])*Q(a[i])).
	// On Verifier: dBV[k] = XOR_{i+j=k} GF128Mul(V(a[i]), V(b[j])).
	var d0, d1 [15][16]byte
	var p0, p1 [8][16]byte
	qsMul8(&d0, &a.tag, &b.tag)
	qsReduceGF256Tags(&p0, &d0)
	if !isVerifier {
		for i := 0; i < 8; i++ {
			aiMask := -uint64((a.val >> i) & 1)
			for j := 0; j < 8; j++ {
				bjMask := -uint64((b.val >> j) & 1)
				xor16Masked(&d1[i+j], &b.tag[j], aiMask)
				xor16Masked(&d1[i+j], &a.tag[i], bjMask)
			}
		}
		qsReduceGF256Tags(&p1, &d1)
		for m := 0; m < 8; m++ {
			xor16(&p1[m], &p1[m], &c.tag[m])
			dispatchGF128MulNoWipe(a1Acc, a1Acc, chi)
			xor16(a1Acc, a1Acc, &p1[m])

			dispatchGF128MulNoWipe(a0OrBVAcc, a0OrBVAcc, chi)
			xor16(a0OrBVAcc, a0OrBVAcc, &p0[m])
		}
	} else {
		var cDelta [16]byte
		for m := 0; m < 8; m++ {
			dispatchGF128MulNoWipe(&cDelta, &c.tag[m], delta)
			xor16(&p0[m], &p0[m], &cDelta)
			dispatchGF128MulNoWipe(a0OrBVAcc, a0OrBVAcc, chi)
			xor16(a0OrBVAcc, a0OrBVAcc, &p0[m])
		}
	}
}

func qsEvalSBoxGate(x, s *qsByteWire, isVerifier bool, delta, chi, a1Acc, a0OrBVAcc *[16]byte) {
	var u, y, w qsByteWire
	qsSqGF256Wire(&u, x)
	qsAffineInvWire(&y, s, isVerifier, delta)
	qsSqGF256Wire(&w, &y)
	qsEvalBilinearConstraint(&u, &y, x, isVerifier, delta, chi, a1Acc, a0OrBVAcc)
	qsEvalBilinearConstraint(&w, x, &y, isVerifier, delta, chi, a1Acc, a0OrBVAcc)
}

func qsMulOrtho128Wires(out *[16]qsByteWire, tHalf *[16]byte, kWires *[16]qsByteWire) {
	clear(out[:])
	// Build the 128 values P_b = GF128Mul(tHalf, x^b) for b = 0..127.
	pCur := *tHalf
	for b := 0; b < 128; b++ {
		byteIdx := b / 8
		bitIdx := b % 8
		wVal := (kWires[byteIdx].val >> bitIdx) & 1
		wTag := &kWires[byteIdx].tag[bitIdx]

		for j := 0; j < 128; j++ {
			if ((pCur[j/8] >> (j % 8)) & 1) != 0 {
				out[j/8].val ^= wVal << (j % 8)
				xor16(&out[j/8].tag[j%8], &out[j/8].tag[j%8], wTag)
			}
		}

		// pCur = GF128Mul(pCur, x)
		lo := binary.LittleEndian.Uint64(pCur[0:8])
		hi := binary.LittleEndian.Uint64(pCur[8:16])
		msb := hi >> 63
		hi = (hi << 1) | (lo >> 63)
		lo = (lo << 1) ^ (0x87 & -msb)
		binary.LittleEndian.PutUint64(pCur[0:8], lo)
		binary.LittleEndian.PutUint64(pCur[8:16], hi)
	}
}

func faestEvalQuickSilverLane(
	p *faestParams,
	mPub, tPub, cPub *[32]byte,
	wFull []byte,
	bitTags [][16]byte, // length 8 * p.lExt
	isVerifier bool,
	deltaLane, chi *[16]byte,
) (a1Acc, a0OrBVAcc [16]byte) {
	wireFromWitnessByte := func(w *qsByteWire, byteOffset int) {
		if !isVerifier {
			w.val = wFull[byteOffset]
		} else {
			w.val = 0
		}
		for b := 0; b < 8; b++ {
			w.tag[b] = bitTags[8*byteOffset+b]
		}
	}

	var k1Wires, k2Wires [32]qsByteWire
	if p.kBytes == 16 {
		for i := 0; i < 16; i++ {
			wireFromWitnessByte(&k1Wires[i], i)
			k1Wires[16+i] = k1Wires[i]
		}
	} else {
		for i := 0; i < 32; i++ {
			wireFromWitnessByte(&k1Wires[i], i)
		}
	}

	if !p.isEM2 {
		qsMulOrtho128Wires((*[16]qsByteWire)(k2Wires[0:16]), (*[16]byte)(tPub[0:16]), (*[16]qsByteWire)(k1Wires[0:16]))
		qsMulOrtho128Wires((*[16]qsByteWire)(k2Wires[16:32]), (*[16]byte)(tPub[16:32]), (*[16]qsByteWire)(k1Wires[16:32]))
	} else {
		for i := 0; i < 16; i++ {
			k2Wires[i] = k1Wires[16+i]
			qsXorByteWire(&k2Wires[16+i], &k1Wires[i], &k1Wires[16+i])
		}
	}

	// Evaluate P1 rounds
	var x0, x1 [16]qsByteWire
	for i := 0; i < 16; i++ {
		qsAddConstByte(&x0[i], &k1Wires[i], mPub[i], isVerifier, deltaLane)
		qsAddConstByte(&x1[i], &k1Wires[16+i], mPub[16+i], isVerifier, deltaLane)
	}

	p1Rounds := 10
	if p.isEM2 {
		p1Rounds = 9
	}

	var a, b, aNext, bNext, s1, mc, x2, t, imc, s2 [16]qsByteWire

	for r := 0; r < p1Rounds; r++ {
		if r%2 == 0 {
			a, b = x0, x1
		} else {
			a, b = x1, x0
		}
		if r < 9 {
			base := p.kBytes + 32*r
			for i := 0; i < 16; i++ {
				wireFromWitnessByte(&aNext[i], base+i)
				wireFromWitnessByte(&bNext[i], base+16+i)
			}
		} else {
			for i := 0; i < 16; i++ {
				qsAddConstByte(&aNext[i], &k2Wires[16+i], cPub[16+i], isVerifier, deltaLane)
				qsAddConstByte(&bNext[i], &k2Wires[i], cPub[i], isVerifier, deltaLane)
			}
		}

		qsInvShiftRowsBlock(&s1, &aNext)
		for j := 0; j < 16; j++ {
			qsEvalSBoxGate(&a[j], &s1[j], isVerifier, deltaLane, chi, &a1Acc, &a0OrBVAcc)
		}

		qsMixColumnsBlock(&mc, &aNext)
		for j := 0; j < 16; j++ {
			qsAddConstByte(&x2[j], &mc[j], roundConstantsP1[r][j], isVerifier, deltaLane)
			qsXorByteWire(&t[j], &b[j], &bNext[j])
		}
		qsInvMixColumnsBlock(&imc, &t)
		qsInvShiftRowsBlock(&s2, &imc)
		for j := 0; j < 16; j++ {
			qsEvalSBoxGate(&x2[j], &s2[j], isVerifier, deltaLane, chi, &a1Acc, &a0OrBVAcc)
		}

		if r%2 == 0 {
			x0, x1 = aNext, bNext
		} else {
			x1, x0 = aNext, bNext
		}
	}

	if p.isEM2 {
		// Evaluate P2 rounds 1..9 from w_p2[0:288] and final state C ^ K1 ^ K2
		baseP2 := p.kBytes + 288
		for i := 0; i < 16; i++ {
			wireFromWitnessByte(&x0[i], baseP2+i)
			wireFromWitnessByte(&x1[i], baseP2+16+i)
		}
		var k12Hi, k12Lo qsByteWire
		for r := 1; r < 10; r++ {
			if r%2 == 0 {
				a, b = x0, x1
			} else {
				a, b = x1, x0
			}
			if r < 9 {
				base := baseP2 + 32*r
				for i := 0; i < 16; i++ {
					wireFromWitnessByte(&aNext[i], base+i)
					wireFromWitnessByte(&bNext[i], base+16+i)
				}
			} else {
				for i := 0; i < 16; i++ {
					qsXorByteWire(&k12Hi, &k1Wires[16+i], &k2Wires[16+i])
					qsXorByteWire(&k12Lo, &k1Wires[i], &k2Wires[i])
					qsAddConstByte(&aNext[i], &k12Hi, cPub[16+i], isVerifier, deltaLane)
					qsAddConstByte(&bNext[i], &k12Lo, cPub[i], isVerifier, deltaLane)
				}
			}

			qsInvShiftRowsBlock(&s1, &aNext)
			for j := 0; j < 16; j++ {
				qsEvalSBoxGate(&a[j], &s1[j], isVerifier, deltaLane, chi, &a1Acc, &a0OrBVAcc)
			}

			qsMixColumnsBlock(&mc, &aNext)
			for j := 0; j < 16; j++ {
				qsAddConstByte(&x2[j], &mc[j], roundConstantsP2[r][j], isVerifier, deltaLane)
				qsXorByteWire(&t[j], &b[j], &bNext[j])
			}
			qsInvMixColumnsBlock(&imc, &t)
			qsInvShiftRowsBlock(&s2, &imc)
			for j := 0; j < 16; j++ {
				qsEvalSBoxGate(&x2[j], &s2[j], isVerifier, deltaLane, chi, &a1Acc, &a0OrBVAcc)
			}

			if r%2 == 0 {
				x0, x1 = aNext, bNext
			} else {
				x1, x0 = aNext, bNext
			}
		}
	}

	return a1Acc, a0OrBVAcc
}

func faestFoldMask128(bitTags [][16]byte, startBit int) (mask [16]byte) {
	var prod, basis [16]byte
	for m := 0; m < 128; m++ {
		basis[m/8] = 1 << (m % 8)
		dispatchGF128MulNoWipe(&prod, &bitTags[startBit+m], &basis)
		xor16(&mask, &mask, &prod)
		basis[m/8] = 0
	}
	return mask
}

//go:noinline
func faestSignCoreBody(p *faestParams, sk, msg, optRand, sigOut []byte) {
	var k32, pSeed, cPub [32]byte
	var pkBytes [64]byte
	var pkLen int
	if p.kBytes == 16 {
		copy(k32[0:16], sk[0:16])
		copy(k32[16:32], sk[0:16])
		copy(pSeed[0:16], sk[16:32])
		copy(pSeed[16:32], sk[16:32])
		copy(cPub[:], sk[32:64])
		copy(pkBytes[0:16], sk[16:32])
		copy(pkBytes[16:48], sk[32:64])
		pkLen = 48
	} else {
		copy(k32[:], sk[0:32])
		copy(pSeed[:], sk[32:64])
		copy(cPub[:], sk[64:96])
		copy(pkBytes[0:32], sk[32:64])
		copy(pkBytes[32:64], sk[64:96])
		pkLen = 64
	}

	tPub, mPub := faestDeriveTM(&pSeed)
	var wFull [608]byte
	copy(wFull[0:p.kBytes], sk[0:p.kBytes])
	if !p.isEM2 {
		var k2, cDummy [32]byte
		var w288 [288]byte
		mulOrtho256Body(&k2, &tPub, &k32)
		dispatchExtractWitness256(&cDummy, &w288, &mPub, &k32, &k2, &roundConstantsP1)
		copy(wFull[p.kBytes:p.lBytes], w288[:])
		clear(k2[:])
		clear(cDummy[:])
		clear(w288[:])
		runtime.KeepAlive(&k2)
		runtime.KeepAlive(&cDummy)
		runtime.KeepAlive(&w288)
	} else {
		var k2, cDummy [32]byte
		var w576 [576]byte
		orthoSigma256Body(&k2, &k32)
		extractWitnessEM2_256Body(&cDummy, &w576, &mPub, &k32, &k2)
		copy(wFull[p.kBytes:p.lBytes], w576[:])
		clear(k2[:])
		clear(cDummy[:])
		clear(w576[:])
		runtime.KeepAlive(&k2)
		runtime.KeepAlive(&cDummy)
		runtime.KeepAlive(&w576)
	}

	// Derive salt (32 B) and tau tree root seeds
	var seedCtxStack [512]byte
	seedCtxLen := len(sk) + p.lambda + len(msg)
	var seedCtx []byte
	if seedCtxLen <= len(seedCtxStack) {
		seedCtx = seedCtxStack[:seedCtxLen]
	} else {
		seedCtx = make([]byte, seedCtxLen)
	}
	copy(seedCtx[0:len(sk)], sk)
	if optRand != nil {
		copy(seedCtx[len(sk):len(sk)+p.lambda], optRand[0:p.lambda])
	}
	copy(seedCtx[len(sk)+p.lambda:], msg)

	var rootBuf [32 + 32*32]byte
	kdfExpandBody(seedCtx, []byte("FAEST-AREION-ROOT"), rootBuf[0:32+p.tau*p.lambda])
	clear(seedCtx)
	runtime.KeepAlive(&seedCtxStack)

	var salt [32]byte
	copy(salt[:], rootBuf[0:32])
	copy(sigOut[0:32], salt[:])

	var u0 [640]byte
	var cTrees [32][640]byte
	var qRows0, qRows1 [128][640]byte
	var hTrees [32][32]byte
	var curNodes, nextNodes, comConcat [1024 * 32]byte
	var ut, rowJ [640]byte

	bitOff := 0
	for t := 0; t < p.tau; t++ {
		dt := p.depths[t]
		nt := 1 << dt
		copy(curNodes[0:p.lambda], rootBuf[32+t*p.lambda:32+(t+1)*p.lambda])

		for lvl := 0; lvl < dt; lvl++ {
			numNodes := 1 << lvl
			for idx := 0; idx < numNodes; idx++ {
				s := curNodes[idx*p.lambda : (idx+1)*p.lambda]
				c0 := nextNodes[(2*idx)*p.lambda : (2*idx+1)*p.lambda]
				c1 := nextNodes[(2*idx+1)*p.lambda : (2*idx+2)*p.lambda]
				faestExpandNode(p.lambda, &salt, t, lvl, idx, s, c0, c1)
			}
			copy(curNodes[0:(2*numNodes)*p.lambda], nextNodes[0:(2*numNodes)*p.lambda])
		}

		clear(ut[0:p.lExt])
		for j := 0; j < nt; j++ {
			sLeaf := curNodes[j*p.lambda : (j+1)*p.lambda]
			comJ := comConcat[j*p.lambda : (j+1)*p.lambda]
			faestExpandLeaf(p.lambda, p.lExt, &salt, t, j, sLeaf, rowJ[0:p.lExt], comJ)
			dispatchVOLEXorRowNoWipe(ut[0:p.lExt], rowJ[0:p.lExt])
			for b := 0; b < dt; b++ {
				if ((j >> b) & 1) != 0 {
					rIdx := bitOff + b
					if rIdx < 128 {
						dispatchVOLEXorRowNoWipe(qRows0[rIdx][0:p.lExt], rowJ[0:p.lExt])
					} else {
						dispatchVOLEXorRowNoWipe(qRows1[rIdx-128][0:p.lExt], rowJ[0:p.lExt])
					}
				}
			}
		}

		if t < p.tau-1 {
			kdfExpandBody(comConcat[0:nt*p.lambda], salt[:], hTrees[t][:])
		}

		if t == 0 {
			copy(u0[0:p.lExt], ut[0:p.lExt])
		} else {
			for i := 0; i < p.lExt; i++ {
				cTrees[t][i] = u0[i] ^ ut[i]
			}
		}
		bitOff += dt
	}

	var dExt [640]byte
	for i := 0; i < p.lBytes; i++ {
		dExt[i] = wFull[i] ^ u0[i]
	}

	// Fiat-Shamir challenge chi
	var fsStack [22528]byte
	fsCap := pkLen + len(msg) + 32 + (p.tau-1)*32 + p.lBytes + (p.tau-1)*p.lExt
	var fsBuf []byte
	if fsCap <= len(fsStack) {
		fsBuf = fsStack[:0]
	} else {
		fsBuf = make([]byte, 0, fsCap)
	}
	fsBuf = append(fsBuf, pkBytes[0:pkLen]...)
	fsBuf = append(fsBuf, msg...)
	fsBuf = append(fsBuf, salt[:]...)
	for t := 0; t < p.tau-1; t++ {
		fsBuf = append(fsBuf, hTrees[t][:]...)
	}
	fsBuf = append(fsBuf, dExt[0:p.lBytes]...)
	for t := 1; t < p.tau; t++ {
		fsBuf = append(fsBuf, cTrees[t][0:p.lExt]...)
	}
	var chi [16]byte
	kdfExpandBody(fsBuf, []byte("FAEST-FS-CHI"), chi[:])
	chi[0] |= 0x01

	// Transpose qRows into bit tags per 128-bit lane and run QuickSilver
	numLanes := p.lambda / 16
	var qsU, wPoly [32]byte
	var bitTagsBuf [8 * 640][16]byte
	bitTags := bitTagsBuf[:8*p.lExt]
	var zeroDelta [16]byte

	for lane := 0; lane < numLanes; lane++ {
		clear(bitTags)
		qRowsLane := &qRows0
		if lane == 1 {
			qRowsLane = &qRows1
		}
		for k := 0; k < 128; k++ {
			row := &qRowsLane[k]
			kByte := k / 8
			kShift := uint(k % 8)
			for byteIdx := 0; byteIdx < p.lExt; byteIdx++ {
				rb := row[byteIdx]
				baseBit := 8 * byteIdx
				bitTags[baseBit+0][kByte] |= ((rb >> 0) & 1) << kShift
				bitTags[baseBit+1][kByte] |= ((rb >> 1) & 1) << kShift
				bitTags[baseBit+2][kByte] |= ((rb >> 2) & 1) << kShift
				bitTags[baseBit+3][kByte] |= ((rb >> 3) & 1) << kShift
				bitTags[baseBit+4][kByte] |= ((rb >> 4) & 1) << kShift
				bitTags[baseBit+5][kByte] |= ((rb >> 5) & 1) << kShift
				bitTags[baseBit+6][kByte] |= ((rb >> 6) & 1) << kShift
				bitTags[baseBit+7][kByte] |= ((rb >> 7) & 1) << kShift
			}
		}
		a1Acc, a0Acc := faestEvalQuickSilverLane(p, &mPub, &tPub, &cPub, wFull[0:p.lBytes], bitTags, false, &zeroDelta, &chi)
		qMask := faestFoldMask128(bitTags, 8*p.lBytes+128*lane)
		for i := 0; i < 16; i++ {
			uMaskByte := u0[p.lBytes+16*lane+i]
			qsU[16*lane+i] = a1Acc[i] ^ uMaskByte
			dExt[p.lBytes+16*lane+i] = qsU[16*lane+i]
			wPoly[16*lane+i] = a0Acc[i] ^ qMask[i]
		}
		clear(a1Acc[:])
		clear(a0Acc[:])
		clear(qMask[:])
		runtime.KeepAlive(&a1Acc)
		runtime.KeepAlive(&a0Acc)
		runtime.KeepAlive(&qMask)
	}

	// Derive opening challenge Delta
	var deltaIn [16 + 32 + 32]byte
	copy(deltaIn[0:16], chi[:])
	copy(deltaIn[16:16+p.lambda], qsU[0:p.lambda])
	copy(deltaIn[16+p.lambda:16+2*p.lambda], wPoly[0:p.lambda])
	var delta [32]byte
	kdfExpandBody(deltaIn[0:16+2*p.lambda], salt[:], delta[0:p.lambda])

	// Pack signature:
	// [0 : 32] -> salt
	// [32 : 32 + lExt] -> dExt
	// [32 + lExt : 32 + tau*lExt] -> c_1 .. c_{tau-1}
	// [32 + tau*lExt : 32 + tau*lExt + 8*lambda*lambda] -> sibling paths
	// [32 + tau*lExt + 8*lambda*lambda : sigSize] -> com_{0, delta_0} .. com_{tau-2, delta_{tau-2}} || Delta
	copy(sigOut[32:32+p.lExt], dExt[0:p.lExt])
	off := 32 + p.lExt
	for t := 1; t < p.tau; t++ {
		copy(sigOut[off:off+p.lExt], cTrees[t][0:p.lExt])
		off += p.lExt
	}

	comOff := off + (8*p.lambda)*p.lambda
	bitOff = 0
	var pathNode, c0, c1 [32]byte
	for t := 0; t < p.tau; t++ {
		dt := p.depths[t]
		deltaT := 0
		for b := 0; b < dt; b++ {
			gBit := bitOff + b
			if ((delta[gBit/8] >> (gBit % 8)) & 1) != 0 {
				deltaT |= 1 << b
			}
		}
		copy(pathNode[0:p.lambda], rootBuf[32+t*p.lambda:32+(t+1)*p.lambda])
		for lvl := 0; lvl < dt; lvl++ {
			parentIdx := deltaT >> (dt - lvl)
			bit := (deltaT >> (dt - 1 - lvl)) & 1
			faestExpandNode(p.lambda, &salt, t, lvl, parentIdx, pathNode[0:p.lambda], c0[0:p.lambda], c1[0:p.lambda])
			if bit == 0 {
				copy(sigOut[off:off+p.lambda], c1[0:p.lambda])
				copy(pathNode[0:p.lambda], c0[0:p.lambda])
			} else {
				copy(sigOut[off:off+p.lambda], c0[0:p.lambda])
				copy(pathNode[0:p.lambda], c1[0:p.lambda])
			}
			off += p.lambda
		}
		if t < p.tau-1 {
			faestExpandLeaf(p.lambda, p.lExt, &salt, t, deltaT, pathNode[0:p.lambda], nil, sigOut[comOff+t*p.lambda:comOff+(t+1)*p.lambda])
		} else {
			copy(sigOut[comOff+t*p.lambda:comOff+(t+1)*p.lambda], delta[0:p.lambda])
		}
		bitOff += dt
	}
	if endOff := comOff + p.tau*p.lambda; endOff < p.sigSize {
		kdfExpandBody(delta[0:p.lambda], salt[:], sigOut[endOff:p.sigSize])
	}

	clear(k32[:])
	clear(pSeed[:])
	clear(cPub[:])
	clear(pkBytes[:])
	clear(tPub[:])
	clear(mPub[:])
	clear(wFull[:])
	clear(rootBuf[:])
	clear(salt[:])
	clear(u0[:])
	clear(cTrees[:])
	clear(qRows0[:])
	clear(qRows1[:])
	clear(hTrees[:])
	clear(curNodes[:])
	clear(nextNodes[:])
	clear(comConcat[:])
	clear(ut[:])
	clear(rowJ[:])
	clear(dExt[:])
	clear(fsStack[:])
	clear(chi[:])
	clear(qsU[:])
	clear(wPoly[:])
	clear(bitTagsBuf[:])
	clear(deltaIn[:])
	clear(delta[:])
	clear(pathNode[:])
	clear(c0[:])
	clear(c1[:])
	runtime.KeepAlive(&k32)
	runtime.KeepAlive(&pSeed)
	runtime.KeepAlive(&cPub)
	runtime.KeepAlive(&pkBytes)
	runtime.KeepAlive(&tPub)
	runtime.KeepAlive(&mPub)
	runtime.KeepAlive(&wFull)
	runtime.KeepAlive(&rootBuf)
	runtime.KeepAlive(&salt)
	runtime.KeepAlive(&u0)
	runtime.KeepAlive(&cTrees)
	runtime.KeepAlive(&qRows0)
	runtime.KeepAlive(&qRows1)
	runtime.KeepAlive(&hTrees)
	runtime.KeepAlive(&curNodes)
	runtime.KeepAlive(&nextNodes)
	runtime.KeepAlive(&comConcat)
	runtime.KeepAlive(&ut)
	runtime.KeepAlive(&rowJ)
	runtime.KeepAlive(&dExt)
	runtime.KeepAlive(&fsStack)
	runtime.KeepAlive(&chi)
	runtime.KeepAlive(&qsU)
	runtime.KeepAlive(&wPoly)
	runtime.KeepAlive(&bitTagsBuf)
	runtime.KeepAlive(&deltaIn)
	runtime.KeepAlive(&delta)
	runtime.KeepAlive(&pathNode)
	runtime.KeepAlive(&c0)
	runtime.KeepAlive(&c1)
}

func faestSignCore(p *faestParams, sk, msg, optRand, sigOut []byte) {
	faestSignCoreBody(p, sk, msg, optRand, sigOut)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func faestVerifyCoreBody(p *faestParams, pk, msg, sig []byte) bool {
	var pSeed, cPub [32]byte
	if p.kBytes == 16 {
		copy(pSeed[0:16], pk[0:16])
		copy(pSeed[16:32], pk[0:16])
		copy(cPub[:], pk[16:48])
	} else {
		copy(pSeed[:], pk[0:32])
		copy(cPub[:], pk[32:64])
	}
	tPub, mPub := faestDeriveTM(&pSeed)

	var salt [32]byte
	copy(salt[:], sig[0:32])
	dExt := sig[32 : 32+p.lExt]
	dWitness := dExt[0:p.lBytes]
	qsU := dExt[p.lBytes:p.lExt]

	cOff := 32 + p.lExt
	sibOff := cOff + (p.tau-1)*p.lExt
	comOff := sibOff + (8*p.lambda)*p.lambda
	deltaSig := sig[comOff+(p.tau-1)*p.lambda : comOff+p.tau*p.lambda]

	var vRows0, vRows1 [128][640]byte
	var hTrees [32][32]byte
	var curNodes, nextNodes, comConcat [1024 * 32]byte
	var rowJ [640]byte
	curSibOff := sibOff
	bitOff := 0

	for t := 0; t < p.tau; t++ {
		dt := p.depths[t]
		nt := 1 << dt
		deltaT := 0
		for b := 0; b < dt; b++ {
			gBit := bitOff + b
			if ((deltaSig[gBit/8] >> (gBit % 8)) & 1) != 0 {
				deltaT |= 1 << b
			}
		}

		for lvl := 0; lvl < dt; lvl++ {
			numNodes := 1 << lvl
			missingParent := deltaT >> (dt - lvl)
			for idx := 0; idx < numNodes; idx++ {
				if idx == missingParent {
					continue
				}
				s := curNodes[idx*p.lambda : (idx+1)*p.lambda]
				c0 := nextNodes[(2*idx)*p.lambda : (2*idx+1)*p.lambda]
				c1 := nextNodes[(2*idx+1)*p.lambda : (2*idx+2)*p.lambda]
				faestExpandNode(p.lambda, &salt, t, lvl, idx, s, c0, c1)
			}
			prefix := deltaT >> (dt - 1 - lvl)
			sibIdx := prefix ^ 1
			copy(nextNodes[sibIdx*p.lambda:(sibIdx+1)*p.lambda], sig[curSibOff:curSibOff+p.lambda])
			curSibOff += p.lambda
			copy(curNodes[0:(2*numNodes)*p.lambda], nextNodes[0:(2*numNodes)*p.lambda])
		}

		for j := 0; j < nt; j++ {
			if j == deltaT {
				if t < p.tau-1 {
					copy(comConcat[j*p.lambda:(j+1)*p.lambda], sig[comOff+t*p.lambda:comOff+(t+1)*p.lambda])
				}
				continue
			}
			sLeaf := curNodes[j*p.lambda : (j+1)*p.lambda]
			var comJ []byte
			if t < p.tau-1 {
				comJ = comConcat[j*p.lambda : (j+1)*p.lambda]
			}
			faestExpandLeaf(p.lambda, p.lExt, &salt, t, j, sLeaf, rowJ[0:p.lExt], comJ)
			diff := j ^ deltaT
			for b := 0; b < dt; b++ {
				if ((diff >> b) & 1) != 0 {
					rIdx := bitOff + b
					if rIdx < 128 {
						dispatchVOLEXorRowNoWipe(vRows0[rIdx][0:p.lExt], rowJ[0:p.lExt])
					} else {
						dispatchVOLEXorRowNoWipe(vRows1[rIdx-128][0:p.lExt], rowJ[0:p.lExt])
					}
				}
			}
		}

		for b := 0; b < dt; b++ {
			if ((deltaT >> b) & 1) != 0 {
				rIdx := bitOff + b
				var vRow []byte
				if rIdx < 128 {
					vRow = vRows0[rIdx][0:p.lExt]
				} else {
					vRow = vRows1[rIdx-128][0:p.lExt]
				}
				if t > 0 {
					ct := sig[cOff+(t-1)*p.lExt : cOff+t*p.lExt]
					dispatchVOLEXorRowNoWipe(vRow, ct)
				}
				dispatchVOLEXorRowNoWipe(vRow, dExt)
			}
		}

		if t < p.tau-1 {
			kdfExpandBody(comConcat[0:nt*p.lambda], salt[:], hTrees[t][:])
		}
		bitOff += dt
	}

	var fsStack [22528]byte
	fsCap := len(pk) + len(msg) + 32 + (p.tau-1)*32 + p.lBytes + (p.tau-1)*p.lExt
	var fsBuf []byte
	if fsCap <= len(fsStack) {
		fsBuf = fsStack[:0]
	} else {
		fsBuf = make([]byte, 0, fsCap)
	}
	fsBuf = append(fsBuf, pk...)
	fsBuf = append(fsBuf, msg...)
	fsBuf = append(fsBuf, salt[:]...)
	for t := 0; t < p.tau-1; t++ {
		fsBuf = append(fsBuf, hTrees[t][:]...)
	}
	fsBuf = append(fsBuf, dWitness...)
	fsBuf = append(fsBuf, sig[cOff:sibOff]...)
	var chi [16]byte
	kdfExpandBody(fsBuf, []byte("FAEST-FS-CHI"), chi[:])
	chi[0] |= 0x01

	numLanes := p.lambda / 16
	var wVerif [32]byte
	var bitTagsBuf [8 * 640][16]byte
	bitTags := bitTagsBuf[:8*p.lExt]

	for lane := 0; lane < numLanes; lane++ {
		clear(bitTags)
		vRowsLane := &vRows0
		if lane == 1 {
			vRowsLane = &vRows1
		}
		for k := 0; k < 128; k++ {
			row := &vRowsLane[k]
			kByte := k / 8
			kShift := uint(k % 8)
			for byteIdx := 0; byteIdx < p.lExt; byteIdx++ {
				rb := row[byteIdx]
				baseBit := 8 * byteIdx
				bitTags[baseBit+0][kByte] |= ((rb >> 0) & 1) << kShift
				bitTags[baseBit+1][kByte] |= ((rb >> 1) & 1) << kShift
				bitTags[baseBit+2][kByte] |= ((rb >> 2) & 1) << kShift
				bitTags[baseBit+3][kByte] |= ((rb >> 3) & 1) << kShift
				bitTags[baseBit+4][kByte] |= ((rb >> 4) & 1) << kShift
				bitTags[baseBit+5][kByte] |= ((rb >> 5) & 1) << kShift
				bitTags[baseBit+6][kByte] |= ((rb >> 6) & 1) << kShift
				bitTags[baseBit+7][kByte] |= ((rb >> 7) & 1) << kShift
			}
		}
		var deltaLane [16]byte
		copy(deltaLane[:], deltaSig[16*lane:16*(lane+1)])
		_, bvAcc := faestEvalQuickSilverLane(p, &mPub, &tPub, &cPub, nil, bitTags, true, &deltaLane, &chi)
		vMask := faestFoldMask128(bitTags, 8*p.lBytes+128*lane)
		for i := 0; i < 16; i++ {
			wVerif[16*lane+i] = bvAcc[i] ^ vMask[i]
		}
		clear(deltaLane[:])
		clear(bvAcc[:])
		clear(vMask[:])
		runtime.KeepAlive(&deltaLane)
		runtime.KeepAlive(&bvAcc)
		runtime.KeepAlive(&vMask)
	}

	var deltaIn [16 + 32 + 32]byte
	copy(deltaIn[0:16], chi[:])
	copy(deltaIn[16:16+p.lambda], qsU)
	copy(deltaIn[16+p.lambda:16+2*p.lambda], wVerif[0:p.lambda])
	var deltaPrime [32]byte
	kdfExpandBody(deltaIn[0:16+2*p.lambda], salt[:], deltaPrime[0:p.lambda])

	ok := subtle.ConstantTimeCompare(deltaSig, deltaPrime[0:p.lambda])
	if endOff := comOff + p.tau*p.lambda; endOff < p.sigSize {
		var expectedTail [640]byte
		tailLen := p.sigSize - endOff
		kdfExpandBody(deltaPrime[0:p.lambda], salt[:], expectedTail[0:tailLen])
		ok &= subtle.ConstantTimeCompare(sig[endOff:p.sigSize], expectedTail[0:tailLen])
		clear(expectedTail[:])
		runtime.KeepAlive(&expectedTail)
	}

	clear(pSeed[:])
	clear(cPub[:])
	clear(tPub[:])
	clear(mPub[:])
	clear(salt[:])
	clear(vRows0[:])
	clear(vRows1[:])
	clear(hTrees[:])
	clear(curNodes[:])
	clear(nextNodes[:])
	clear(comConcat[:])
	clear(rowJ[:])
	clear(fsStack[:])
	clear(chi[:])
	clear(wVerif[:])
	clear(bitTagsBuf[:])
	clear(deltaIn[:])
	clear(deltaPrime[:])
	runtime.KeepAlive(&pSeed)
	runtime.KeepAlive(&cPub)
	runtime.KeepAlive(&tPub)
	runtime.KeepAlive(&mPub)
	runtime.KeepAlive(&salt)
	runtime.KeepAlive(&vRows0)
	runtime.KeepAlive(&vRows1)
	runtime.KeepAlive(&hTrees)
	runtime.KeepAlive(&curNodes)
	runtime.KeepAlive(&nextNodes)
	runtime.KeepAlive(&comConcat)
	runtime.KeepAlive(&rowJ)
	runtime.KeepAlive(&fsStack)
	runtime.KeepAlive(&chi)
	runtime.KeepAlive(&wVerif)
	runtime.KeepAlive(&bitTagsBuf)
	runtime.KeepAlive(&deltaIn)
	runtime.KeepAlive(&deltaPrime)
	return ok == 1
}

func faestVerifyCore(p *faestParams, pk, msg, sig []byte) bool {
	ok := faestVerifyCoreBody(p, pk, msg, sig)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return ok
}

// FAESTKeygen128s generates a FAEST-Areion-128s keypair from a 32-byte seed.
func FAESTKeygen128s(seed *[32]byte) (pk [48]byte, sk [64]byte) {
	return faestKeygen128Core(seed)
}

// FAESTSign128s signs msg under a FAEST-Areion-128s secret key.
func FAESTSign128s(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [6448]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParams128s, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTVerify128s verifies a FAEST-Areion-128s signature.
func FAESTVerify128s(pk *[48]byte, msg []byte, sig *[6448]byte) bool {
	return faestVerifyCore(&faestParams128s, pk[:], msg, sig[:])
}

// FAESTKeygen128f generates a FAEST-Areion-128f keypair from a 32-byte seed.
func FAESTKeygen128f(seed *[32]byte) (pk [48]byte, sk [64]byte) {
	return faestKeygen128Core(seed)
}

// FAESTSign128f signs msg under a FAEST-Areion-128f secret key.
func FAESTSign128f(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [7456]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParams128f, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTVerify128f verifies a FAEST-Areion-128f signature.
func FAESTVerify128f(pk *[48]byte, msg []byte, sig *[7456]byte) bool {
	return faestVerifyCore(&faestParams128f, pk[:], msg, sig[:])
}

// FAESTKeygen256s generates a FAEST-Areion-256s keypair from a 64-byte seed.
func FAESTKeygen256s(seed *[64]byte) (pk [64]byte, sk [96]byte) {
	return faestKeygen256Core(seed, false)
}

// FAESTSign256s signs msg under a FAEST-Areion-256s secret key.
func FAESTSign256s(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [18208]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParams256s, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTVerify256s verifies a FAEST-Areion-256s signature.
func FAESTVerify256s(pk *[64]byte, msg []byte, sig *[18208]byte) bool {
	return faestVerifyCore(&faestParams256s, pk[:], msg, sig[:])
}

// FAESTKeygen256f generates a FAEST-Areion-256f keypair from a 64-byte seed.
func FAESTKeygen256f(seed *[64]byte) (pk [64]byte, sk [96]byte) {
	return faestKeygen256Core(seed, false)
}

// FAESTSign256f signs msg under a FAEST-Areion-256f secret key.
func FAESTSign256f(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [20512]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParams256f, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTVerify256f verifies a FAEST-Areion-256f signature.
func FAESTVerify256f(pk *[64]byte, msg []byte, sig *[20512]byte) bool {
	return faestVerifyCore(&faestParams256f, pk[:], msg, sig[:])
}

// FAESTEM2Keygen256s generates a FAEST-Areion-EM2-256s keypair from a 64-byte seed.
func FAESTEM2Keygen256s(seed *[64]byte) (pk [64]byte, sk [96]byte) {
	return faestKeygen256Core(seed, true)
}

// FAESTEM2Sign256s signs msg under a FAEST-Areion-EM2-256s secret key.
func FAESTEM2Sign256s(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [25696]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParamsEM2256s, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTEM2Verify256s verifies a FAEST-Areion-EM2-256s signature.
func FAESTEM2Verify256s(pk *[64]byte, msg []byte, sig *[25696]byte) bool {
	return faestVerifyCore(&faestParamsEM2256s, pk[:], msg, sig[:])
}

// FAESTEM2Keygen256f generates a FAEST-Areion-EM2-256f keypair from a 64-byte seed.
func FAESTEM2Keygen256f(seed *[64]byte) (pk [64]byte, sk [96]byte) {
	return faestKeygen256Core(seed, true)
}

// FAESTEM2Sign256f signs msg under a FAEST-Areion-EM2-256f secret key.
func FAESTEM2Sign256f(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [30368]byte) {
	var opt []byte
	if optRand != nil {
		opt = optRand[:]
	}
	faestSignCore(&faestParamsEM2256f, sk[:], msg, opt, sig[:])
	return sig
}

// FAESTEM2Verify256f verifies a FAEST-Areion-EM2-256f signature.
func FAESTEM2Verify256f(pk *[64]byte, msg []byte, sig *[30368]byte) bool {
	return faestVerifyCore(&faestParamsEM2256f, pk[:], msg, sig[:])
}

// ============================================================================
// 5. crypto.Signer Key Types (FAESTPublicKey, FAESTPrivateKey, SLHDSAPublicKey, SLHDSAPrivateKey)
// ============================================================================

// FAESTPublicKey represents a FAEST-Areion public verification key.
type FAESTPublicKey struct {
	Variant string
	Bytes   []byte
}

// Equal reports whether pub and x have the same value.
func (pub *FAESTPublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*FAESTPublicKey)
	if !ok || pub.Variant != other.Variant {
		return false
	}
	return subtle.ConstantTimeCompare(pub.Bytes, other.Bytes) == 1
}

// Verify verifies sig over msg under pub.
func (pub *FAESTPublicKey) Verify(msg, sig []byte) bool {
	switch pub.Variant {
	case "128s":
		if len(pub.Bytes) != FAEST128PublicKeySize || len(sig) != FAEST128sSigSize {
			return false
		}
		return FAESTVerify128s((*[48]byte)(pub.Bytes), msg, (*[6448]byte)(sig))
	case "128f":
		if len(pub.Bytes) != FAEST128PublicKeySize || len(sig) != FAEST128fSigSize {
			return false
		}
		return FAESTVerify128f((*[48]byte)(pub.Bytes), msg, (*[7456]byte)(sig))
	case "256s":
		if len(pub.Bytes) != FAEST256PublicKeySize || len(sig) != FAEST256sSigSize {
			return false
		}
		return FAESTVerify256s((*[64]byte)(pub.Bytes), msg, (*[18208]byte)(sig))
	case "256f":
		if len(pub.Bytes) != FAEST256PublicKeySize || len(sig) != FAEST256fSigSize {
			return false
		}
		return FAESTVerify256f((*[64]byte)(pub.Bytes), msg, (*[20512]byte)(sig))
	case "em2-256s":
		if len(pub.Bytes) != FAESTEM2256PublicKeySize || len(sig) != FAESTEM2256sSigSize {
			return false
		}
		return FAESTEM2Verify256s((*[64]byte)(pub.Bytes), msg, (*[25696]byte)(sig))
	case "em2-256f":
		if len(pub.Bytes) != FAESTEM2256PublicKeySize || len(sig) != FAESTEM2256fSigSize {
			return false
		}
		return FAESTEM2Verify256f((*[64]byte)(pub.Bytes), msg, (*[30368]byte)(sig))
	default:
		return false
	}
}

// FAESTPrivateKey represents a FAEST-Areion signing key implementing crypto.Signer.
type FAESTPrivateKey struct {
	Variant string
	Bytes   []byte
	Pub     FAESTPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *FAESTPrivateKey) Public() crypto.PublicKey {
	return &priv.Pub
}

// Sign signs digest (or full message when opts == crypto.Hash(0) or nil) using priv.
func (priv *FAESTPrivateKey) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	switch priv.Variant {
	case "128s":
		if len(priv.Bytes) != FAEST128SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-128s secret key size")
		}
		var opt [16]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTSign128s((*[64]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "128f":
		if len(priv.Bytes) != FAEST128SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-128f secret key size")
		}
		var opt [16]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTSign128f((*[64]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "256s":
		if len(priv.Bytes) != FAEST256SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-256s secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTSign256s((*[96]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "256f":
		if len(priv.Bytes) != FAEST256SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-256f secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTSign256f((*[96]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "em2-256s":
		if len(priv.Bytes) != FAESTEM2256SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-EM2-256s secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTEM2Sign256s((*[96]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "em2-256f":
		if len(priv.Bytes) != FAESTEM2256SecretKeySize {
			return nil, errors.New("areionpq: invalid FAEST-EM2-256f secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := FAESTEM2Sign256f((*[96]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	default:
		return nil, errors.New("areionpq: unknown FAEST variant")
	}
}

// SLHDSAPublicKey represents an SLH-DSA-Areion public verification key.
type SLHDSAPublicKey struct {
	Variant string
	Bytes   []byte
}

// Equal reports whether pub and x have the same value.
func (pub *SLHDSAPublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*SLHDSAPublicKey)
	if !ok || pub.Variant != other.Variant {
		return false
	}
	return subtle.ConstantTimeCompare(pub.Bytes, other.Bytes) == 1
}

// Verify verifies sig over msg under pub.
func (pub *SLHDSAPublicKey) Verify(msg, sig []byte) bool {
	switch pub.Variant {
	case "128f":
		if len(pub.Bytes) != SLHDSA128PublicKeySize || len(sig) != SLHDSA128fSigSize {
			return false
		}
		return SLHDSAVerify128f((*[32]byte)(pub.Bytes), msg, (*[17088]byte)(sig))
	case "128s":
		if len(pub.Bytes) != SLHDSA128PublicKeySize || len(sig) != SLHDSA128sSigSize {
			return false
		}
		return SLHDSAVerify128s((*[32]byte)(pub.Bytes), msg, (*[7856]byte)(sig))
	case "256f":
		if len(pub.Bytes) != SLHDSA256PublicKeySize || len(sig) != SLHDSA256fSigSize {
			return false
		}
		return SLHDSAVerify256f((*[64]byte)(pub.Bytes), msg, (*[49856]byte)(sig))
	case "256s":
		if len(pub.Bytes) != SLHDSA256PublicKeySize || len(sig) != SLHDSA256sSigSize {
			return false
		}
		return SLHDSAVerify256s((*[64]byte)(pub.Bytes), msg, (*[29792]byte)(sig))
	case "tem-256f":
		if len(pub.Bytes) != SLHDSA256PublicKeySize || len(sig) != SLHDSA256fSigSize {
			return false
		}
		return SLHDSATEMVerify256f((*[64]byte)(pub.Bytes), msg, (*[49856]byte)(sig))
	default:
		return false
	}
}

// SLHDSAPrivateKey represents an SLH-DSA-Areion signing key implementing crypto.Signer.
type SLHDSAPrivateKey struct {
	Variant string
	Bytes   []byte
	Pub     SLHDSAPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *SLHDSAPrivateKey) Public() crypto.PublicKey {
	return &priv.Pub
}

// Sign signs digest (or full message when opts == crypto.Hash(0) or nil) using priv.
func (priv *SLHDSAPrivateKey) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	switch priv.Variant {
	case "128f":
		if len(priv.Bytes) != SLHDSA128SecretKeySize {
			return nil, errors.New("areionpq: invalid SLH-DSA-128f secret key size")
		}
		var opt [16]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := SLHDSASign128f((*[64]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "128s":
		if len(priv.Bytes) != SLHDSA128SecretKeySize {
			return nil, errors.New("areionpq: invalid SLH-DSA-128s secret key size")
		}
		var opt [16]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := SLHDSASign128s((*[64]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "256f":
		if len(priv.Bytes) != SLHDSA256SecretKeySize {
			return nil, errors.New("areionpq: invalid SLH-DSA-256f secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := SLHDSASign256f((*[128]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "256s":
		if len(priv.Bytes) != SLHDSA256SecretKeySize {
			return nil, errors.New("areionpq: invalid SLH-DSA-256s secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := SLHDSASign256s((*[128]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	case "tem-256f":
		if len(priv.Bytes) != SLHDSA256SecretKeySize {
			return nil, errors.New("areionpq: invalid SLH-DSA-TEM-256f secret key size")
		}
		var opt [32]byte
		_, _ = io.ReadFull(randReader, opt[:])
		sig := SLHDSATEMSign256f((*[128]byte)(priv.Bytes), digest, &opt)
		return sig[:], nil
	default:
		return nil, errors.New("areionpq: unknown SLH-DSA variant")
	}
}
