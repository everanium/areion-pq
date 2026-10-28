package areionpq

import (
	"encoding/binary"
	"runtime"
	"testing"
	"unsafe"
)

var areionPQSink uint64

//go:noinline
func leakyAreionFrame(secret uint64, i int) {
	var frame [64]uint64
	for j := range frame {
		frame[j] = secret
	}
	areionPQSink = frame[(i+1)%len(frame)]
}

func bytesToNonZeroWords(bufs ...[]byte) []uint64 {
	var out []uint64
	for _, b := range bufs {
		for i := 0; i+8 <= len(b); i += 8 {
			wLE := binary.LittleEndian.Uint64(b[i : i+8])
			if wLE != 0 {
				out = append(out, wLE)
			}
			if wNat := binary.NativeEndian.Uint64(b[i : i+8]); wNat != 0 && wNat != wLE {
				out = append(out, wNat)
			}
		}
	}
	return out
}

func isNonTrivialWord32(u uint32) bool {
	return u != 0 && u != uint32(areionResidueSentinel&0xFFFFFFFF) &&
		(u&0xff) != 0 && ((u>>8)&0xff) != 0 && ((u>>16)&0xff) != 0 && ((u>>24)&0xff) != 0
}

func matchWord32On32Bit(w, t uint64) (uint64, bool) {
	if unsafe.Sizeof(uintptr(0)) != 4 {
		return 0, false
	}
	wLo := uint32(w)
	wHi := uint32(w >> 32)
	tLo := uint32(t)
	tHi := uint32(t >> 32)
	if isNonTrivialWord32(tLo) && (wLo == tLo || wHi == tLo) {
		return uint64(tLo), true
	}
	if isNonTrivialWord32(tHi) && (wLo == tHi || wHi == tHi) {
		return uint64(tHi), true
	}
	return 0, false
}

func scanForAreionWords(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i, w := range window {
		if w == 0 || (i < areionStackWords && w == areionResidueSentinel) {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
			if i < areionStackWords {
				if m32, ok := matchWord32On32Bit(w, t); ok {
					return m32, i * 8, true
				}
			}
		}
	}
	return 0, 0, false
}

func scanForAreionWordsInStack(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := 0; i < areionStackWords; i++ {
		w := window[i]
		if w == 0 || w == areionResidueSentinel {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
			if m32, ok := matchWord32On32Bit(w, t); ok {
				return m32, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func scanForAreionWordsInRegs(window *[areionTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := areionStackWords; i < len(window); i++ {
		w := window[i]
		if w == 0 {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

// TestFusedKernelsLeaveNoSecretInFrame verifies that every hardware-accelerated
// and software-fallback primitive in areionpq wipes its vector registers,
// scratch GPRs, and stack frame slots before returning across all supported tiers.
func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping raw stack/register frame inspection under -race instrumentation")
	}
	res := new([areionTotalWords]uint64)

	t.Run("NegativeControl_Stack", func(t *testing.T) {
		const canary = uint64(0xCAFEBABE13579BDF)
		idx := 3
		written := captureAreionFrameAndRegResidue(func() {
			leakyAreionFrame(canary, idx)
		}, res)
		runtime.KeepAlive(areionPQSink)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForAreionWordsInStack(res, []uint64{canary}); !found {
			t.Fatal("negative control failed: stack canary written to callee frame was not observed in stack window")
		}
	})

	t.Run("NegativeControl_SIMDAndGPR", func(t *testing.T) {
		if !hasSIMDRegProbe {
			t.Skip("register probe assembly not active on this build target")
		}
		const mask = uint64(0x5555555555555555)
		const secret = uint64(0xFEEDFACECAFEBEEF)
		masked := secret ^ mask
		written := captureAreionFrameAndRegResidue(func() {
			dirtySIMDRegForTest(masked)
		}, res)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForAreionWordsInRegs(res, []uint64{secret}); !found {
			t.Fatal("negative control failed: register canary left in X2/V2/R12 was not observed by post-RET register dump")
		}
	})

	origTier := Tier()
	defer func() { _ = SetTier(origTier) }()

	for _, tier := range AvailableTiers() {
		t.Run("tier="+tier, func(t *testing.T) {
			if err := SetTier(tier); err != nil {
				t.Fatalf("SetTier(%s): %v", tier, err)
			}

			// 1. Direct architecture assembly kernels
			if tier != "purego" {
				testAreionPQArchAsmKernels(t, tier, res)
			}

			// 2. Dispatched internal hooks (pointer-based, zero stack/reg residue for all inputs & outputs)
			c := new([32]byte)
			w := new([288]byte)
			m := new([32]byte)
			k1 := new([32]byte)
			k2 := new([32]byte)
			for i := 0; i < 32; i++ {
				m[i] = byte(0x11 + i*3)
				k1[i] = byte(0x57 + i*5)
				k2[i] = byte(0x9B + i*7)
			}
			if written := captureAreionFrameAndRegResidue(func() {
				dispatchExtractWitness256(c, w, m, k1, k2, &roundConstantsP1)
			}, res); written == 0 {
				t.Fatalf("[%s] dispatchExtractWitness256: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(m[:], k1[:], k2[:], c[:], w[:])); found {
				t.Fatalf("[%s] dispatchExtractWitness256 leaked word %#016x at offset %d", tier, word, off)
			}

			if written := captureAreionFrameAndRegResidue(func() {
				_ = VerifyWitness256(m, c, k1, k2, w)
			}, res); written == 0 {
				t.Fatalf("[%s] VerifyWitness256: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(m[:], k1[:], k2[:], c[:])); found {
				t.Fatalf("[%s] VerifyWitness256 leaked word %#016x at offset %d", tier, word, off)
			}

			// 3. Dispatched GF(2^128) Mul and PolyMAC
			gfOut := new([16]byte)
			gfA := new([16]byte)
			gfB := new([16]byte)
			for i := 0; i < 16; i++ {
				gfA[i] = byte(0x29 + i*7)
				gfB[i] = byte(0x6D + i*11)
			}
			if written := captureAreionFrameAndRegResidue(func() {
				dispatchGF128Mul(gfOut, gfA, gfB)
			}, res); written == 0 {
				t.Fatalf("[%s] dispatchGF128Mul: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(gfA[:], gfB[:], gfOut[:])); found {
				t.Fatalf("[%s] dispatchGF128Mul leaked word %#016x at offset %d", tier, word, off)
			}

			pmAcc := new([16]byte)
			pmOrigAcc := new([16]byte)
			pmA := new([64]byte)
			pmB := new([64]byte)
			pmChi := new([16]byte)
			for i := 0; i < 16; i++ {
				pmOrigAcc[i] = byte(0x33 + i*5)
				pmChi[i] = byte(0x77 + i*9)
			}
			for i := 0; i < 64; i++ {
				pmA[i] = byte(0x43 + i*3)
				pmB[i] = byte(0x8B + i*7)
			}
			*pmAcc = *pmOrigAcc
			if written := captureAreionFrameAndRegResidue(func() {
				dispatchGF128PolyMAC(pmAcc, pmA[:], pmB[:], pmChi)
			}, res); written == 0 {
				t.Fatalf("[%s] dispatchGF128PolyMAC: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(pmOrigAcc[:], pmAcc[:], pmA[:], pmB[:], pmChi[:])); found {
				t.Fatalf("[%s] dispatchGF128PolyMAC leaked word %#016x at offset %d", tier, word, off)
			}

			// 4. Dispatched VOLE XOR Row & SLH WOTS Chain 256x4
			vxDst := new([137]byte)
			vxOrig := new([137]byte)
			vxSrc := new([137]byte)
			for i := range vxDst {
				vxOrig[i] = byte(0x1D + i*5)
				vxSrc[i] = byte(0xA9 + i*3)
			}
			*vxDst = *vxOrig
			if written := captureAreionFrameAndRegResidue(func() {
				dispatchVOLEXorRow(vxDst[:], vxSrc[:])
			}, res); written == 0 {
				t.Fatalf("[%s] dispatchVOLEXorRow: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(vxOrig[:], vxDst[:], vxSrc[:])); found {
				t.Fatalf("[%s] dispatchVOLEXorRow leaked word %#016x at offset %d", tier, word, off)
			}

			wotsOut := new([4][32]byte)
			wotsIn := new([4][32]byte)
			wotsAdrs := new([4][32]byte)
			kpub1 := new([32]byte)
			kpub2 := new([32]byte)
			for i := 0; i < 32; i++ {
				kpub1[i] = byte(0x51 + i*3)
				kpub2[i] = byte(0x93 + i*5)
			}
			for l := 0; l < 4; l++ {
				for i := 0; i < 32; i++ {
					wotsIn[l][i] = byte(0x21 + l*17 + i*7)
					wotsAdrs[l][i] = byte(0x11 + l*13 + i*3)
				}
			}
			if written := captureAreionFrameAndRegResidue(func() {
				dispatchSLHWOTSChain256x4(wotsOut, wotsIn, wotsAdrs, kpub1, kpub2, 0, 3)
			}, res); written == 0 {
				t.Fatalf("[%s] dispatchSLHWOTSChain256x4: probe missed stack window", tier)
			}
			wotsTargets := bytesToNonZeroWords(kpub1[:], kpub2[:])
			for l := 0; l < 4; l++ {
				wotsTargets = append(wotsTargets, bytesToNonZeroWords(wotsIn[l][:], wotsOut[l][:])...)
			}
			if word, off, found := scanForAreionWords(res, wotsTargets); found {
				t.Fatalf("[%s] dispatchSLHWOTSChain256x4 leaked word %#016x at offset %d", tier, word, off)
			}

			// 5. Public API secret-input zeroization checks
			cPub := new([32]byte)
			wPub := new([288]byte)
			if written := captureAreionFrameAndRegResidue(func() {
				*cPub, *wPub = ExtractWitness256(m, k1, k2)
			}, res); written == 0 {
				t.Fatalf("[%s] ExtractWitness256: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(m[:], k1[:], k2[:])); found {
				t.Fatalf("[%s] ExtractWitness256 leaked secret input word %#016x at offset %d", tier, word, off)
			}

			cEM2 := new([32]byte)
			wEM2 := new([576]byte)
			if written := captureAreionFrameAndRegResidue(func() {
				*cEM2, *wEM2 = ExtractWitnessEM2_256(m, k1, k2)
			}, res); written == 0 {
				t.Fatalf("[%s] ExtractWitnessEM2_256: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(m[:], k1[:], k2[:])); found {
				t.Fatalf("[%s] ExtractWitnessEM2_256 leaked secret input word %#016x at offset %d", tier, word, off)
			}

			if written := captureAreionFrameAndRegResidue(func() {
				_ = VerifyWitnessEM2_256(m, cEM2, k1, k2, wEM2)
			}, res); written == 0 {
				t.Fatalf("[%s] VerifyWitnessEM2_256: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(m[:], k1[:], k2[:], cEM2[:])); found {
				t.Fatalf("[%s] VerifyWitnessEM2_256 leaked word %#016x at offset %d", tier, word, off)
			}

			gfPubOut := new([16]byte)
			if written := captureAreionFrameAndRegResidue(func() {
				*gfPubOut = GF128Mul(gfA, gfB)
			}, res); written == 0 {
				t.Fatalf("[%s] GF128Mul: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(gfA[:], gfB[:])); found {
				t.Fatalf("[%s] GF128Mul leaked word %#016x at offset %d", tier, word, off)
			}

			pmSliceA := make([][16]byte, 4)
			pmSliceB := make([][16]byte, 4)
			for i := 0; i < 4; i++ {
				copy(pmSliceA[i][:], pmA[16*i:16*(i+1)])
				copy(pmSliceB[i][:], pmB[16*i:16*(i+1)])
			}
			if written := captureAreionFrameAndRegResidue(func() {
				*gfPubOut = GF128PolyMAC(pmSliceA, pmSliceB, pmChi)
			}, res); written == 0 {
				t.Fatalf("[%s] GF128PolyMAC: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(pmA[:], pmB[:], pmChi[:])); found {
				t.Fatalf("[%s] GF128PolyMAC leaked word %#016x at offset %d", tier, word, off)
			}

			// 6. KDFExpand and TEM2SIVEncryptInPlace / TEM2SIVDecryptInPlace
			secret := new([32]byte)
			ctx := new([16]byte)
			kdfOut := new([128]byte)
			for i := range secret {
				secret[i] = byte(0x63 + i*5)
			}
			for i := range ctx {
				ctx[i] = byte(0x41 + i*3)
			}
			if written := captureAreionFrameAndRegResidue(func() {
				KDFExpand(secret[:], ctx[:], kdfOut[:])
			}, res); written == 0 {
				t.Fatalf("[%s] KDFExpand: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(secret[:], ctx[:])); found {
				t.Fatalf("[%s] KDFExpand leaked word %#016x at offset %d", tier, word, off)
			}

			sivKey := new([128]byte)
			sivNonce := new([32]byte)
			sivAD := new([32]byte)
			sivPT := new([96]byte)
			sivCT := new([96]byte)
			sivDec := new([96]byte)
			sivTag := new([32]byte)
			for i := range sivKey {
				sivKey[i] = byte(0x71 + i*3)
			}
			for i := range sivNonce {
				sivNonce[i] = byte(0x83 + i*5)
				sivAD[i] = byte(0x97 + i*7)
			}
			for i := range sivPT {
				sivPT[i] = byte(0xA1 + i*11)
			}
			if written := captureAreionFrameAndRegResidue(func() {
				*sivTag = TEM2SIVEncryptInPlace(sivKey, sivNonce, sivAD[:], sivCT[:], sivPT[:])
			}, res); written == 0 {
				t.Fatalf("[%s] TEM2SIVEncryptInPlace: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(sivKey[:], sivNonce[:], sivAD[:], sivPT[:])); found {
				t.Fatalf("[%s] TEM2SIVEncryptInPlace leaked secret word %#016x at offset %d", tier, word, off)
			}

			if written := captureAreionFrameAndRegResidue(func() {
				_ = TEM2SIVDecryptInPlace(sivKey, sivNonce, sivAD[:], sivDec[:], sivCT[:], sivTag)
			}, res); written == 0 {
				t.Fatalf("[%s] TEM2SIVDecryptInPlace: probe missed stack window", tier)
			}
			if word, off, found := scanForAreionWords(res, bytesToNonZeroWords(sivKey[:], sivNonce[:], sivAD[:], sivCT[:])); found {
				t.Fatalf("[%s] TEM2SIVDecryptInPlace leaked word %#016x at offset %d", tier, word, off)
			}
		})
	}
}
