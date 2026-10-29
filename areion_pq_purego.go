package areionpq

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
	"runtime"

	"github.com/everanium/areion"
)

// bsState holds up to four 128-bit AES blocks in 64-bit bitsliced form.
type bsState [8]uint64

const (
	bsByte0Mask = 0x0101010101010101
)

//go:noinline
func wipeSoftwareStack() {
	var frame [128]uint64
	clear(frame[:])
	runtime.KeepAlive(&frame)
}

func bsPrepWord(u uint64) uint64 {
	t := ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	t = ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	return u
}

func bsUnprepWord(u uint64) uint64 {
	t := ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	t = ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	return u
}

func bsPrepBlock(lo, hi uint64) (uint64, uint64) {
	u0 := uint64(uint32(lo)) | (hi << 32)
	u1 := (lo >> 32) | (hi & 0xffffffff00000000)
	return bsPrepWord(u0), bsPrepWord(u1)
}

func bsUnprepBlock(u0, u1 uint64) (uint64, uint64) {
	u0 = bsUnprepWord(u0)
	u1 = bsUnprepWord(u1)
	lo := uint64(uint32(u0)) | (u1 << 32)
	hi := (u0 >> 32) | (u1 & 0xffffffff00000000)
	return lo, hi
}

func bsPack1(q *bsState, b0 *[16]byte) {
	lo := binary.LittleEndian.Uint64(b0[0:8])
	hi := binary.LittleEndian.Uint64(b0[8:16])
	u0, u1 := bsPrepBlock(lo, hi)
	q[0] = (u0 & bsByte0Mask) | ((u1 & bsByte0Mask) << 4)
	q[1] = ((u0 >> 1) & bsByte0Mask) | (((u1 >> 1) & bsByte0Mask) << 4)
	q[2] = ((u0 >> 2) & bsByte0Mask) | (((u1 >> 2) & bsByte0Mask) << 4)
	q[3] = ((u0 >> 3) & bsByte0Mask) | (((u1 >> 3) & bsByte0Mask) << 4)
	q[4] = ((u0 >> 4) & bsByte0Mask) | (((u1 >> 4) & bsByte0Mask) << 4)
	q[5] = ((u0 >> 5) & bsByte0Mask) | (((u1 >> 5) & bsByte0Mask) << 4)
	q[6] = ((u0 >> 6) & bsByte0Mask) | (((u1 >> 6) & bsByte0Mask) << 4)
	q[7] = ((u0 >> 7) & bsByte0Mask) | (((u1 >> 7) & bsByte0Mask) << 4)
}

func bsUnpack1(q *bsState, b0 *[16]byte) {
	u0 := (q[0] & bsByte0Mask) |
		((q[1] & bsByte0Mask) << 1) |
		((q[2] & bsByte0Mask) << 2) |
		((q[3] & bsByte0Mask) << 3) |
		((q[4] & bsByte0Mask) << 4) |
		((q[5] & bsByte0Mask) << 5) |
		((q[6] & bsByte0Mask) << 6) |
		((q[7] & bsByte0Mask) << 7)
	u1 := ((q[0] >> 4) & bsByte0Mask) |
		(((q[1] >> 4) & bsByte0Mask) << 1) |
		(((q[2] >> 4) & bsByte0Mask) << 2) |
		(((q[3] >> 4) & bsByte0Mask) << 3) |
		(((q[4] >> 4) & bsByte0Mask) << 4) |
		(((q[5] >> 4) & bsByte0Mask) << 5) |
		(((q[6] >> 4) & bsByte0Mask) << 6) |
		(((q[7] >> 4) & bsByte0Mask) << 7)
	lo, hi := bsUnprepBlock(u0, u1)
	binary.LittleEndian.PutUint64(b0[0:8], lo)
	binary.LittleEndian.PutUint64(b0[8:16], hi)
}

// bsSubBytes evaluates the constant-time Boyar-Peralta combinational AES S-box circuit.
func bsSubBytes(q *bsState) {
	u0, u1, u2, u3, u4, u5, u6, u7 := q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]

	y14 := u3 ^ u5
	y13 := u0 ^ u6
	y9 := u0 ^ u3
	y8 := u0 ^ u5
	t0 := u1 ^ u2
	y1 := t0 ^ u7
	y4 := y1 ^ u3
	y12 := y13 ^ y14
	y2 := y1 ^ u0
	y5 := y1 ^ u6
	y3 := y5 ^ y8
	t1 := u4 ^ y12
	y15 := t1 ^ u5
	y20 := t1 ^ u1
	y6 := y15 ^ u7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := u7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := u0 ^ y16

	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & u7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18

	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41

	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & u7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8

	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	s0 := t59 ^ t63
	s6 := ^(t56 ^ t62)
	s7 := ^(t48 ^ t60)
	t67 := t64 ^ t65
	s3 := t53 ^ t66
	s4 := t51 ^ t66
	s5 := t47 ^ t65
	s1 := ^(t64 ^ s3)
	s2 := ^(t55 ^ t67)

	q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0] = s0, s1, s2, s3, s4, s5, s6, s7
}

func bsShiftRows(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		q[k] = uint64(uint16(x)) |
			uint64(bits.RotateLeft16(uint16(x>>16), -4))<<16 |
			uint64(bits.RotateLeft16(uint16(x>>32), 8))<<32 |
			uint64(bits.RotateLeft16(uint16(x>>48), 4))<<48
	}
}

func bsInvShiftRows(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		q[k] = uint64(uint16(x)) |
			uint64(bits.RotateLeft16(uint16(x>>16), 4))<<16 |
			uint64(bits.RotateLeft16(uint16(x>>32), 8))<<32 |
			uint64(bits.RotateLeft16(uint16(x>>48), -4))<<48
	}
}

func bsMixColumns(q *bsState) {
	var a, b [8]uint64
	for k := 0; k < 8; k++ {
		r1 := bits.RotateLeft64(q[k], -16)
		ak := q[k] ^ r1
		a[k] = ak
		b[k] = r1 ^ bits.RotateLeft64(ak, 32)
	}
	a7 := a[7]
	q[0] = a7 ^ b[0]
	q[1] = a[0] ^ a7 ^ b[1]
	q[2] = a[1] ^ b[2]
	q[3] = a[2] ^ a7 ^ b[3]
	q[4] = a[3] ^ a7 ^ b[4]
	q[5] = a[4] ^ b[5]
	q[6] = a[5] ^ b[6]
	q[7] = a[6] ^ b[7]
}

func bsInvMixColumns(q *bsState) {
	var d, u, f [8]uint64
	for k := 0; k < 8; k++ {
		d[k] = q[k] ^ bits.RotateLeft64(q[k], 32)
	}
	d6, d7 := d[6], d[7]
	d67 := d6 ^ d7
	u[0] = d6
	u[1] = d67
	u[2] = d[0] ^ d7
	u[3] = d[1] ^ d6
	u[4] = d[2] ^ d67
	u[5] = d[3] ^ d7
	u[6] = d[4]
	u[7] = d[5]

	for k := 0; k < 8; k++ {
		f[k] = u[k] ^ bits.RotateLeft64(u[k], -16)
	}
	bsMixColumns(q)
	f7 := f[7]
	q[0] ^= u[0] ^ f7
	q[1] ^= u[1] ^ f[0] ^ f7
	q[2] ^= u[2] ^ f[1]
	q[3] ^= u[3] ^ f[2] ^ f7
	q[4] ^= u[4] ^ f[3] ^ f7
	q[5] ^= u[5] ^ f[4]
	q[6] ^= u[6] ^ f[5]
	q[7] ^= u[7] ^ f[6]
}

func xor16(dst, a, b *[16]byte) {
	lo := binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8])
	hi := binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16])
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func xor16Masked(dst, src *[16]byte, mask uint64) {
	lo := binary.LittleEndian.Uint64(dst[0:8]) ^ (binary.LittleEndian.Uint64(src[0:8]) & mask)
	hi := binary.LittleEndian.Uint64(dst[8:16]) ^ (binary.LittleEndian.Uint64(src[8:16]) & mask)
	binary.LittleEndian.PutUint64(dst[0:8], lo)
	binary.LittleEndian.PutUint64(dst[8:16], hi)
}

func xor32(dst, a, b *[32]byte) {
	for i := 0; i < 32; i += 8 {
		v := binary.LittleEndian.Uint64(a[i:i+8]) ^ binary.LittleEndian.Uint64(b[i:i+8])
		binary.LittleEndian.PutUint64(dst[i:i+8], v)
	}
}

func softInvShiftRows(dst, in *[16]byte) {
	var q bsState
	bsPack1(&q, in)
	bsInvShiftRows(&q)
	bsUnpack1(&q, dst)
}

func softMixColumns(dst, in *[16]byte) {
	var q bsState
	bsPack1(&q, in)
	bsMixColumns(&q)
	bsUnpack1(&q, dst)
}

func softInvMixColumns(dst, in *[16]byte) {
	var q bsState
	bsPack1(&q, in)
	bsInvMixColumns(&q)
	bsUnpack1(&q, dst)
}

//go:noinline
func extractWitness256SoftwareBody(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte) {
	var x0, x1, aNext, u, bNext [16]byte
	var q, qRC bsState
	for i := 0; i < 16; i++ {
		x0[i] = m[i] ^ k1[i]
		x1[i] = m[16+i] ^ k1[16+i]
	}

	for r := 0; r < 10; r++ {
		if r%2 == 0 {
			bsPack1(&q, &x0)
		} else {
			bsPack1(&q, &x1)
		}
		bsSubBytes(&q)
		bsShiftRows(&q)
		bsUnpack1(&q, &aNext)

		bsMixColumns(&q)
		bsPack1(&qRC, &rc[r])
		for k := 0; k < 8; k++ {
			q[k] ^= qRC[k]
		}
		bsSubBytes(&q)
		bsShiftRows(&q)
		bsMixColumns(&q)
		bsUnpack1(&q, &u)

		if r%2 == 0 {
			xor16(&bNext, &x1, &u)
			x0 = aNext
			x1 = bNext
		} else {
			xor16(&bNext, &x0, &u)
			x1 = aNext
			x0 = bNext
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
}

// extractWitness256Software extracts the 32-byte ciphertext c and 288-byte
// 9-round S-box witness w for 10-round Areion-256 in constant-time bitsliced software.
func extractWitness256Software(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte) {
	extractWitness256SoftwareBody(c, w, m, k1, k2, rc)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

func ctDiff32(a, b *[32]byte) uint64 {
	return (binary.LittleEndian.Uint64(a[0:8]) ^ binary.LittleEndian.Uint64(b[0:8])) |
		(binary.LittleEndian.Uint64(a[8:16]) ^ binary.LittleEndian.Uint64(b[8:16])) |
		(binary.LittleEndian.Uint64(a[16:24]) ^ binary.LittleEndian.Uint64(b[16:24])) |
		(binary.LittleEndian.Uint64(a[24:32]) ^ binary.LittleEndian.Uint64(b[24:32]))
}

func ctDiff288(a, b *[288]byte) uint64 {
	return ctDiff32((*[32]byte)(a[0:32]), (*[32]byte)(b[0:32])) |
		ctDiff32((*[32]byte)(a[32:64]), (*[32]byte)(b[32:64])) |
		ctDiff32((*[32]byte)(a[64:96]), (*[32]byte)(b[64:96])) |
		ctDiff32((*[32]byte)(a[96:128]), (*[32]byte)(b[96:128])) |
		ctDiff32((*[32]byte)(a[128:160]), (*[32]byte)(b[128:160])) |
		ctDiff32((*[32]byte)(a[160:192]), (*[32]byte)(b[160:192])) |
		ctDiff32((*[32]byte)(a[192:224]), (*[32]byte)(b[192:224])) |
		ctDiff32((*[32]byte)(a[224:256]), (*[32]byte)(b[224:256])) |
		ctDiff32((*[32]byte)(a[256:288]), (*[32]byte)(b[256:288]))
}

//go:noinline
func verifyWitness256SoftwareBody(m, c, k1, k2 *[32]byte, w *[288]byte, rc *[10][16]byte) bool {
	var x0, x1, a, b, aNext, bNext, t, xLayer1, sLayer1, xLayer2, sLayer2, tmpMC, tmpIMC [16]byte
	for i := 0; i < 16; i++ {
		x0[i] = m[i] ^ k1[i]
		x1[i] = m[16+i] ^ k1[16+i]
	}

	var diff byte
	for r := 0; r < 10; r++ {
		if r%2 == 0 {
			a, b = x0, x1
		} else {
			a, b = x1, x0
		}
		if r < 9 {
			copy(aNext[:], w[32*r:32*r+16])
			copy(bNext[:], w[32*r+16:32*r+32])
		} else {
			for i := 0; i < 16; i++ {
				aNext[i] = c[16+i] ^ k2[16+i]
				bNext[i] = c[i] ^ k2[i]
			}
		}

		xLayer1 = a
		softInvShiftRows(&sLayer1, &aNext)
		for j := 0; j < 16; j++ {
			xj := xLayer1[j]
			sj := sLayer1[j]
			uj := GF256Sq(xj)
			yj := GF256AffineInv(sj)
			wj := GF256Sq(yj)
			diff |= (GF256Mul(uj, yj) ^ xj) | (GF256Mul(wj, xj) ^ yj)
		}

		softMixColumns(&tmpMC, &aNext)
		xor16(&xLayer2, &tmpMC, &rc[r])
		xor16(&t, &b, &bNext)
		softInvMixColumns(&tmpIMC, &t)
		softInvShiftRows(&sLayer2, &tmpIMC)
		for j := 0; j < 16; j++ {
			xj := xLayer2[j]
			sj := sLayer2[j]
			uj := GF256Sq(xj)
			yj := GF256AffineInv(sj)
			wj := GF256Sq(yj)
			diff |= (GF256Mul(uj, yj) ^ xj) | (GF256Mul(wj, xj) ^ yj)
		}

		if r%2 == 0 {
			x0, x1 = aNext, bNext
		} else {
			x1, x0 = aNext, bNext
		}
	}

	return subtle.ConstantTimeByteEq(diff, 0) == 1
}

func verifyWitness256Internal(m, c, k1, k2 *[32]byte, w *[288]byte, rc *[10][16]byte) bool {
	if hasHardwareExtractWitness256() {
		var cExp [32]byte
		var wExp [288]byte
		dispatchExtractWitness256(&cExp, &wExp, m, k1, k2, rc)
		diff := ctDiff32(c, &cExp) | ctDiff288(w, &wExp)
		clear(cExp[:])
		clear(wExp[:])
		runtime.KeepAlive(&cExp)
		runtime.KeepAlive(&wExp)
		clobberScratchGPRs()
		return diff == 0
	}
	ok := verifyWitness256SoftwareBody(m, c, k1, k2, w, rc)
	wipeSoftwareStack()
	clobberScratchGPRs()
	return ok
}

// clmul64 computes the constant-time 128-bit carry-less product of two 64-bit polynomials.
func clmul64(x, y uint64) (lo, hi uint64) {
	for i := uint(0); i < 64; i++ {
		mask := -((y >> i) & 1)
		lo ^= (x << i) & mask
		if i > 0 {
			hi ^= (x >> (64 - i)) & mask
		}
	}
	return lo, hi
}

//go:noinline
func gf128MulCore(out, a, b *[16]byte) {
	a0 := binary.LittleEndian.Uint64(a[0:8])
	a1 := binary.LittleEndian.Uint64(a[8:16])
	b0 := binary.LittleEndian.Uint64(b[0:8])
	b1 := binary.LittleEndian.Uint64(b[8:16])

	l0, l1 := clmul64(a0, b0)
	h0, h1 := clmul64(a1, b1)
	m0, m1 := clmul64(a0^a1, b0^b1)
	m0 ^= l0 ^ h0
	m1 ^= l1 ^ h1

	c0 := l0
	c1 := l1 ^ m0
	h0 ^= m1

	// Reduce c_high = (h0, h1) modulo x^128 + x^7 + x^2 + x + 1 (0x87).
	t1 := (h1 << 7) ^ (h1 << 2) ^ (h1 << 1) ^ h1
	t1Hi := (h1 >> 57) ^ (h1 >> 62) ^ (h1 >> 63)
	h0 ^= t1Hi
	r1 := c1 ^ t1 ^ (h0 >> 57) ^ (h0 >> 62) ^ (h0 >> 63)
	r0 := c0 ^ (h0 << 7) ^ (h0 << 2) ^ (h0 << 1) ^ h0

	binary.LittleEndian.PutUint64(out[0:8], r0)
	binary.LittleEndian.PutUint64(out[8:16], r1)
}

func gf128MulSoftware(out, a, b *[16]byte) {
	gf128MulCore(out, a, b)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func gf128PolyMACSoftwareBody(acc *[16]byte, a, b []byte, chi *[16]byte) {
	n := len(a) / 16
	if len(b)/16 < n {
		n = len(b) / 16
	}
	var ai, bi, prod [16]byte
	cur := *acc
	for i := 0; i < n; i++ {
		copy(ai[:], a[16*i:16*(i+1)])
		copy(bi[:], b[16*i:16*(i+1)])
		gf128MulCore(&prod, &ai, &bi)
		gf128MulCore(&cur, &cur, chi)
		xor16(&cur, &cur, &prod)
	}
	*acc = cur
}

func gf128PolyMACSoftware(acc *[16]byte, a, b []byte, chi *[16]byte) {
	gf128PolyMACSoftwareBody(acc, a, b, chi)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func gf128PolyMACBlocksSoftwareBody(acc *[16]byte, a, b [][16]byte, chi *[16]byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var prod [16]byte
	cur := *acc
	for i := 0; i < n; i++ {
		gf128MulCore(&prod, &a[i], &b[i])
		gf128MulCore(&cur, &cur, chi)
		xor16(&cur, &cur, &prod)
	}
	*acc = cur
}

func gf128PolyMACBlocksSoftware(acc *[16]byte, a, b [][16]byte, chi *[16]byte) {
	gf128PolyMACBlocksSoftwareBody(acc, a, b, chi)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func voleXorRowCore(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.LittleEndian.Uint64(dst[i:i+8]) ^ binary.LittleEndian.Uint64(src[i:i+8])
		binary.LittleEndian.PutUint64(dst[i:i+8], v)
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

func voleXorRowSoftware(dst, src []byte) {
	voleXorRowCore(dst, src)
	wipeSoftwareStack()
	clobberScratchGPRs()
}

//go:noinline
func slhWOTSChain256x4SoftwareBody(out *[4][32]byte, in *[4][32]byte, adrs *[4][32]byte, kpub1, kpub2 *[32]byte, startStep, steps int) {
	cur := *in
	if steps <= 0 {
		*out = cur
		return
	}
	var b512, p512 [4][64]byte
	kp10 := binary.LittleEndian.Uint64(kpub1[0:8])
	kp11 := binary.LittleEndian.Uint64(kpub1[8:16])
	kp12 := binary.LittleEndian.Uint64(kpub1[16:24])
	kp13 := binary.LittleEndian.Uint64(kpub1[24:32])
	kp20 := binary.LittleEndian.Uint64(kpub2[0:8])
	kp21 := binary.LittleEndian.Uint64(kpub2[8:16])
	kp22 := binary.LittleEndian.Uint64(kpub2[16:24])
	kp23 := binary.LittleEndian.Uint64(kpub2[24:32])
	kp1BE28 := binary.BigEndian.Uint32(kpub1[28:32])

	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(b512[lane][0:8], binary.LittleEndian.Uint64(adrs[lane][0:8])^kp10)
		binary.LittleEndian.PutUint64(b512[lane][8:16], binary.LittleEndian.Uint64(adrs[lane][8:16])^kp11)
		binary.LittleEndian.PutUint64(b512[lane][16:24], binary.LittleEndian.Uint64(adrs[lane][16:24])^kp12)
		binary.LittleEndian.PutUint64(b512[lane][24:32], binary.LittleEndian.Uint64(adrs[lane][24:32])^kp13)
	}

	for step := startStep; step < startStep+steps; step++ {
		stepMasked := uint32(step) ^ kp1BE28
		for lane := 0; lane < 4; lane++ {
			binary.BigEndian.PutUint32(b512[lane][28:32], stepMasked)
			binary.LittleEndian.PutUint64(b512[lane][32:40], binary.LittleEndian.Uint64(cur[lane][0:8])^kp20)
			binary.LittleEndian.PutUint64(b512[lane][40:48], binary.LittleEndian.Uint64(cur[lane][8:16])^kp21)
			binary.LittleEndian.PutUint64(b512[lane][48:56], binary.LittleEndian.Uint64(cur[lane][16:24])^kp22)
			binary.LittleEndian.PutUint64(b512[lane][56:64], binary.LittleEndian.Uint64(cur[lane][24:32])^kp23)
		}
		p512 = b512
		areion.Permute512x4(&p512)
		for lane := 0; lane < 4; lane++ {
			w0 := binary.LittleEndian.Uint64(p512[lane][8:16]) ^ binary.LittleEndian.Uint64(b512[lane][8:16])
			w1 := binary.LittleEndian.Uint64(p512[lane][24:32]) ^ binary.LittleEndian.Uint64(b512[lane][24:32])
			w2 := binary.LittleEndian.Uint64(p512[lane][32:40]) ^ binary.LittleEndian.Uint64(b512[lane][32:40])
			w3 := binary.LittleEndian.Uint64(p512[lane][48:56]) ^ binary.LittleEndian.Uint64(b512[lane][48:56])
			binary.LittleEndian.PutUint64(cur[lane][0:8], w0)
			binary.LittleEndian.PutUint64(cur[lane][8:16], w1)
			binary.LittleEndian.PutUint64(cur[lane][16:24], w2)
			binary.LittleEndian.PutUint64(cur[lane][24:32], w3)
		}
	}

	*out = cur
}

func slhWOTSChain256x4Software(out *[4][32]byte, in *[4][32]byte, adrs *[4][32]byte, kpub1, kpub2 *[32]byte, startStep, steps int) {
	slhWOTSChain256x4SoftwareBody(out, in, adrs, kpub1, kpub2, startStep, steps)
	wipeSoftwareStack()
	clobberScratchGPRs()
}
