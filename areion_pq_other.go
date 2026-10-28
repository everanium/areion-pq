//go:build (!amd64 && !arm64) || purego

package areionpq

func hasHardwareExtractWitness256() bool {
	return false
}

func dispatchExtractWitness256(c *[32]byte, w *[288]byte, m, k1, k2 *[32]byte, rc *[10][16]byte) {
	extractWitness256Software(c, w, m, k1, k2, rc)
}

func dispatchGF128Mul(out, a, b *[16]byte) {
	gf128MulSoftware(out, a, b)
}

func dispatchGF128MulNoWipe(out, a, b *[16]byte) {
	gf128MulCore(out, a, b)
}

func dispatchGF128PolyMAC(acc *[16]byte, a, b []byte, chi *[16]byte) {
	gf128PolyMACSoftware(acc, a, b, chi)
}

func dispatchGF128PolyMACBlocks(acc *[16]byte, a, b [][16]byte, chi *[16]byte) {
	gf128PolyMACBlocksSoftware(acc, a, b, chi)
}

func dispatchVOLEXorRow(dst, src []byte) {
	voleXorRowSoftware(dst, src)
}

func dispatchVOLEXorRowNoWipe(dst, src []byte) {
	voleXorRowCore(dst, src)
}

func dispatchSLHWOTSChain256x4(out *[4][32]byte, in *[4][32]byte, adrs *[4][32]byte, kpub1, kpub2 *[32]byte, startStep, steps int) {
	slhWOTSChain256x4Software(out, in, adrs, kpub1, kpub2, startStep, steps)
}

func clobberScratchGPRs() {}
