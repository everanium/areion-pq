//go:build arm64 && !purego

package areionpq

//go:noescape
func areion256ExtractWitnessAsm(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte)

//go:noescape
func gf128MulPMULLAsm(out, a, b *[16]byte)

//go:noescape
func gf128PolyMACPMULLAsm(acc *[16]byte, a, b *byte, count int, chi *[16]byte)

//go:noescape
func voleXorRowNEONAsm(dst, src *byte, n int)

//go:noescape
func clobberScratchGPRs()

func hasHardwareExtractWitness256() bool {
	return hasARMCrypto && TierCode() != TierPureGo
}

func dispatchExtractWitness256(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte) {
	if hasARMCrypto && TierCode() != TierPureGo {
		areion256ExtractWitnessAsm(c, w, m, k1, k2, rc)
		return
	}
	extractWitness256Software(c, w, m, k1, k2, rc)
}

func dispatchGF128Mul(out, a, b *[16]byte) {
	if hasPMULL && TierCode() != TierPureGo {
		gf128MulPMULLAsm(out, a, b)
		return
	}
	gf128MulSoftware(out, a, b)
}

func dispatchGF128MulNoWipe(out, a, b *[16]byte) {
	if hasPMULL && TierCode() != TierPureGo {
		gf128MulPMULLAsm(out, a, b)
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
	if hasPMULL && TierCode() != TierPureGo {
		gf128PolyMACPMULLAsm(acc, &a[0], &b[0], n, chi)
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
	if hasPMULL && TierCode() != TierPureGo {
		gf128PolyMACPMULLAsm(acc, &a[0][0], &b[0][0], n, chi)
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
	if TierCode() != TierPureGo {
		voleXorRowNEONAsm(&dst[0], &src[0], n)
		return
	}
	voleXorRowSoftware(dst, src)
}

func dispatchVOLEXorRowNoWipe(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	if n <= 0 {
		return
	}
	if TierCode() != TierPureGo {
		voleXorRowNEONAsm(&dst[0], &src[0], n)
		return
	}
	voleXorRowCore(dst, src)
}

func dispatchSLHWOTSChain256x4(out *[4][32]byte, in *[4][32]byte, adrs *[4][32]byte, kpub1, kpub2 *[32]byte, startStep, steps int) {
	slhWOTSChain256x4Software(out, in, adrs, kpub1, kpub2, startStep, steps)
}
