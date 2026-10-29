//go:build amd64 && !purego

package areionpq

//go:noescape
func areion256ExtractWitnessAsm(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte)

//go:noescape
func areion256ExtractWitnessVexAsm(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte)

//go:noescape
func gf128MulPCLMULAsm(out, a, b *[16]byte)

//go:noescape
func gf128MulVPCLMULAsm(out, a, b *[16]byte)

//go:noescape
func gf128PolyMACPCLMULAsm(acc *[16]byte, a, b *byte, count int, chi *[16]byte)

//go:noescape
func gf128PolyMACVPCLMULAsm(acc *[16]byte, a, b *byte, count int, chi *[16]byte)

//go:noescape
func voleXorRowSSE2Asm(dst, src *byte, n int)

//go:noescape
func voleXorRowAVX2Asm(dst, src *byte, n int)

//go:noescape
func voleXorRowAVX512Asm(dst, src *byte, n int)

//go:noescape
func clobberScratchGPRs()

func hasHardwareExtractWitness256() bool {
	return TierCode() >= TierAESNI
}

func dispatchExtractWitness256(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte) {
	tier := TierCode()
	if tier >= TierVEX {
		areion256ExtractWitnessVexAsm(c, w, m, k1, k2, rc)
		return
	}
	if tier >= TierAESNI {
		areion256ExtractWitnessAsm(c, w, m, k1, k2, rc)
		return
	}
	extractWitness256Software(c, w, m, k1, k2, rc)
}

func dispatchGF128Mul(out, a, b *[16]byte) {
	tier := TierCode()
	if hasVPCLMULQDQ && tier >= TierVEX {
		gf128MulVPCLMULAsm(out, a, b)
		return
	}
	if hasPCLMULQDQ && tier >= TierAESNI {
		gf128MulPCLMULAsm(out, a, b)
		return
	}
	gf128MulSoftware(out, a, b)
}

func dispatchGF128MulNoWipe(out, a, b *[16]byte) {
	tier := TierCode()
	if hasVPCLMULQDQ && tier >= TierVEX {
		gf128MulVPCLMULAsm(out, a, b)
		return
	}
	if hasPCLMULQDQ && tier >= TierAESNI {
		gf128MulPCLMULAsm(out, a, b)
		return
	}
	gf128MulCore(out, a, b)
}

func dispatchGF128PolyMAC(acc *[16]byte, a, b []byte, chi *[16]byte) {
	n := len(a) / 16
	if nb := len(b) / 16; nb < n {
		n = nb
	}
	if n <= 0 {
		clobberScratchGPRs()
		return
	}
	tier := TierCode()
	if hasVPCLMULQDQ && tier >= TierVEX {
		gf128PolyMACVPCLMULAsm(acc, &a[0], &b[0], n, chi)
		return
	}
	if hasPCLMULQDQ && tier >= TierAESNI {
		gf128PolyMACPCLMULAsm(acc, &a[0], &b[0], n, chi)
		return
	}
	gf128PolyMACSoftware(acc, a, b, chi)
}

func dispatchGF128PolyMACBlocks(acc *[16]byte, a, b [][16]byte, chi *[16]byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n <= 0 {
		clobberScratchGPRs()
		return
	}
	tier := TierCode()
	if hasVPCLMULQDQ && tier >= TierVEX {
		gf128PolyMACVPCLMULAsm(acc, &a[0][0], &b[0][0], n, chi)
		return
	}
	if hasPCLMULQDQ && tier >= TierAESNI {
		gf128PolyMACPCLMULAsm(acc, &a[0][0], &b[0][0], n, chi)
		return
	}
	gf128PolyMACBlocksSoftware(acc, a, b, chi)
}

func dispatchVOLEXorRow(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	if n <= 0 {
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && tier >= TierAVX512:
		voleXorRowAVX512Asm(&dst[0], &src[0], n)
	case hasAVX2 && tier >= TierVAESAVX2:
		voleXorRowAVX2Asm(&dst[0], &src[0], n)
	case tier >= TierAESNI:
		voleXorRowSSE2Asm(&dst[0], &src[0], n)
	default:
		voleXorRowSoftware(dst, src)
	}
}

func dispatchVOLEXorRowNoWipe(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	if n <= 0 {
		return
	}
	tier := TierCode()
	switch {
	case hasAVX512 && tier >= TierAVX512:
		voleXorRowAVX512Asm(&dst[0], &src[0], n)
	case hasAVX2 && tier >= TierVAESAVX2:
		voleXorRowAVX2Asm(&dst[0], &src[0], n)
	case tier >= TierAESNI:
		voleXorRowSSE2Asm(&dst[0], &src[0], n)
	default:
		voleXorRowCore(dst, src)
	}
}

func dispatchSLHWOTSChain256x4(out *[4][32]byte, in *[4][32]byte, adrs *[4][32]byte, kpub1, kpub2 *[32]byte, startStep, steps int) {
	slhWOTSChain256x4Software(out, in, adrs, kpub1, kpub2, startStep, steps)
}
