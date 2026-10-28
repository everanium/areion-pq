//go:build amd64 && !purego

package areionpq

import (
	"runtime/debug"
	"testing"
	"unsafe"
)

//go:noescape
func dumpSIMDRegs(dst *[96]uint64, hasAVX512 bool)

//go:noescape
func dirtySIMDRegForTest(masked uint64)

const (
	hasSIMDRegProbe       = true
	areionResidueGap      = 1 << 10
	areionResiduePad      = 2 << 10
	areionResidueWindow   = 16 << 10
	areionResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
	areionSIMDWords       = 96
	areionStackWords      = areionResidueWindow / 8
	areionTotalWords      = areionStackWords + areionSIMDWords
)

//go:noinline
func areionResidueGrow(i int) byte {
	var pad [4 * areionResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
//go:nocheckptr
func areionResidueProbe(fn func(), res []uint64, regs *[areionSIMDWords]uint64, avx512 bool) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -areionResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = areionResidueSentinel
	}
	areionResidueDeep(fn, 0, regs, avx512)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func areionResidueDeep(fn func(), i int, regs *[areionSIMDWords]uint64, avx512 bool) byte {
	var pad [areionResiduePad]byte
	pad[i] = 1
	dumpSIMDRegs(regs, avx512)
	fn()
	dumpSIMDRegs(regs, avx512)
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureAreionFrameAndRegResidue(call func(), dst *[areionTotalWords]uint64) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	avx512 := hasAVX512 && TierCode() >= TierAVX512
	done := make(chan struct{})
	go func() {
		defer close(done)
		areionResidueGrow(0)
		var simd [areionSIMDWords]uint64
		areionResidueProbe(call, dst[:areionStackWords], &simd, avx512)
		copy(dst[areionStackWords:], simd[:])
	}()
	<-done
	written := 0
	for i := 0; i < areionStackWords; i++ {
		if dst[i] != areionResidueSentinel {
			written++
		}
	}
	return written
}

func testAreionPQArchAsmKernels(t *testing.T, tier string, res *[areionTotalWords]uint64) {
	runExtract := func(name string, fn func(*[32]byte, *[288]byte, *[32]byte, *[32]byte, *[32]byte, *[10][16]byte)) {
		c := new([32]byte)
		w := new([288]byte)
		m := new([32]byte)
		k1 := new([32]byte)
		k2 := new([32]byte)
		for i := 0; i < 32; i++ {
			m[i] = byte(0x17 + i*3)
			k1[i] = byte(0x53 + i*5)
			k2[i] = byte(0x91 + i*7)
		}
		if written := captureAreionFrameAndRegResidue(func() {
			fn(c, w, m, k1, k2, &roundConstantsP1)
		}, res); written == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(m[:], k1[:], k2[:], c[:], w[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, name, word, off)
		}
	}

	runGF128Mul := func(name string, fn func(*[16]byte, *[16]byte, *[16]byte)) {
		out := new([16]byte)
		a := new([16]byte)
		b := new([16]byte)
		for i := 0; i < 16; i++ {
			a[i] = byte(0x23 + i*7)
			b[i] = byte(0x67 + i*11)
		}
		if written := captureAreionFrameAndRegResidue(func() {
			fn(out, a, b)
		}, res); written == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(a[:], b[:], out[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, name, word, off)
		}
	}

	runPolyMAC := func(name string, fn func(*[16]byte, *byte, *byte, int, *[16]byte)) {
		acc := new([16]byte)
		origAcc := new([16]byte)
		a := new([64]byte)
		b := new([64]byte)
		chi := new([16]byte)
		for i := 0; i < 16; i++ {
			origAcc[i] = byte(0x31 + i*5)
			chi[i] = byte(0x73 + i*9)
		}
		for i := 0; i < 64; i++ {
			a[i] = byte(0x41 + i*3)
			b[i] = byte(0x89 + i*7)
		}
		*acc = *origAcc
		if written := captureAreionFrameAndRegResidue(func() {
			fn(acc, &a[0], &b[0], 4, chi)
		}, res); written == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(origAcc[:], acc[:], a[:], b[:], chi[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, name, word, off)
		}
	}

	runVOLEXor := func(name string, fn func(*byte, *byte, int)) {
		dst := new([137]byte)
		origDst := new([137]byte)
		src := new([137]byte)
		for i := range dst {
			origDst[i] = byte(0x19 + i*5)
			src[i] = byte(0xA3 + i*3)
		}
		*dst = *origDst
		if written := captureAreionFrameAndRegResidue(func() {
			fn(&dst[0], &src[0], len(dst))
		}, res); written == 0 {
			t.Fatalf("[%s] %s: probe missed stack window", tier, name)
		}
		targets := bytesToNonZeroWords(origDst[:], dst[:], src[:])
		if word, off, found := scanForAreionWords(res, targets); found {
			t.Fatalf("[%s] %s leaked word %#016x at offset %d", tier, name, word, off)
		}
	}

	switch tier {
	case "aesni":
		runExtract("areion256ExtractWitnessAsm", areion256ExtractWitnessAsm)
		if hasPCLMULQDQ {
			runGF128Mul("gf128MulPCLMULAsm", gf128MulPCLMULAsm)
			runPolyMAC("gf128PolyMACPCLMULAsm", gf128PolyMACPCLMULAsm)
		}
		runVOLEXor("voleXorRowSSE2Asm", voleXorRowSSE2Asm)
	case "vex":
		runExtract("areion256ExtractWitnessVexAsm", areion256ExtractWitnessVexAsm)
		if hasVPCLMULQDQ {
			runGF128Mul("gf128MulVPCLMULAsm", gf128MulVPCLMULAsm)
			runPolyMAC("gf128PolyMACVPCLMULAsm", gf128PolyMACVPCLMULAsm)
		}
		runVOLEXor("voleXorRowSSE2Asm", voleXorRowSSE2Asm)
	case "vaesavx2":
		runExtract("areion256ExtractWitnessVexAsm", areion256ExtractWitnessVexAsm)
		if hasVPCLMULQDQ {
			runGF128Mul("gf128MulVPCLMULAsm", gf128MulVPCLMULAsm)
			runPolyMAC("gf128PolyMACVPCLMULAsm", gf128PolyMACVPCLMULAsm)
		}
		if hasAVX2 {
			runVOLEXor("voleXorRowAVX2Asm", voleXorRowAVX2Asm)
		}
	case "avx512":
		runExtract("areion256ExtractWitnessVexAsm", areion256ExtractWitnessVexAsm)
		if hasVPCLMULQDQ {
			runGF128Mul("gf128MulVPCLMULAsm", gf128MulVPCLMULAsm)
			runPolyMAC("gf128PolyMACVPCLMULAsm", gf128PolyMACVPCLMULAsm)
		}
		runVOLEXor("voleXorRowAVX512Asm", voleXorRowAVX512Asm)
	}
}
