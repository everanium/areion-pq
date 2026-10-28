package main

import (
	"fmt"
	"math"
	"math/bits"
	"math/rand/v2"

	"github.com/everanium/areion"
)

func slhExpandSeed128Ref(pkSeed, skSeed *[16]byte) (kPub, kSK [64]byte) {
	var p, s [32]byte
	copy(p[0:16], pkSeed[:])
	copy(p[16:32], pkSeed[:])
	copy(s[0:16], skSeed[:])
	copy(s[16:32], skSeed[:])
	return slhExpandSeed256Ref(&p, &s)
}

func slhExpandSeed256Ref(pkSeed, skSeed *[32]byte) (kPub, kSK [64]byte) {
	kp1 := areion.DM256(pkSeed)
	kp2 := *pkSeed
	areion.Permute256P2(&kp2)
	for i := 0; i < 32; i++ {
		kp2[i] ^= pkSeed[i]
	}
	copy(kPub[0:32], kp1[:])
	copy(kPub[32:64], kp2[:])

	var s1, s2 [32]byte
	for i := 0; i < 32; i++ {
		s1[i] = skSeed[i] ^ kp1[i]
		s2[i] = skSeed[i] ^ kp2[i]
	}
	areion.Permute256(&s1)
	areion.Permute256P2(&s2)
	for i := 0; i < 32; i++ {
		s1[i] ^= skSeed[i]
		s2[i] ^= skSeed[i]
	}
	copy(kSK[0:32], s1[:])
	copy(kSK[32:64], s2[:])
	return kPub, kSK
}

func slhCompactADRSRef(adrs *[32]byte) (c [16]byte) {
	c[0] = adrs[3]
	copy(c[1:9], adrs[8:16])
	c[9] = adrs[19]
	copy(c[10:12], adrs[22:24])
	c[12] = adrs[27]
	copy(c[13:16], adrs[29:32])
	return c
}

func slhPRF256Ref(kSK *[64]byte, adrs *[32]byte) [32]byte {
	return areion.SoEM256(kSK, adrs)
}

func slhF128Ref(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1 *[16]byte) (out [16]byte) {
	var b [64]byte
	copy(b[0:16], pkSeed[:])
	copy(b[16:48], adrs[:])
	copy(b[48:64], m1[:])
	for i := 0; i < 64; i++ {
		b[i] ^= kPub[i]
	}
	d := areion.DM512(&b)
	copy(out[:], d[0:16])
	return out
}

func slhF256Ref(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	var b [64]byte
	for i := 0; i < 32; i++ {
		b[i] = adrs[i] ^ kPub[i]
		b[32+i] = m1[i] ^ kPub[32+i]
	}
	return areion.DM512(&b)
}

func slhFTEM256Ref(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	// Profile II (TEM-MiddleTweak): M1 is passed in tweak slot, ADRS in message slot, then ^ M1
	enc := areion.TEMEncrypt256(kPub, m1, adrs)
	for i := 0; i < 32; i++ {
		enc[i] ^= m1[i]
	}
	return enc
}

// slhFNaiveTEM256 is the broken naive feed-forward construction where ADRS is
// in the tweak slot and M1 is in the message slot:
//   TEMEncrypt256(K_pub, ADRS, M1) ^ M1 = P1(M1 ^ W(ADRS)) ^ W(ADRS) ^ M1 = DM256(M1 ^ W(ADRS)).
func slhFNaiveTEM256(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte {
	enc := areion.TEMEncrypt256(kPub, adrs, m1)
	for i := 0; i < 32; i++ {
		enc[i] ^= m1[i]
	}
	return enc
}

func slhH128Ref(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1, m2 *[16]byte) (out [16]byte) {
	c := slhCompactADRSRef(adrs)
	var b [64]byte
	copy(b[0:16], pkSeed[:])
	copy(b[16:32], c[:])
	copy(b[32:48], m1[:])
	copy(b[48:64], m2[:])
	for i := 0; i < 64; i++ {
		b[i] ^= kPub[i]
	}
	d := areion.DM512(&b)
	copy(out[:], d[0:16])
	return out
}

func slhH256Ref(kPub *[64]byte, adrs *[32]byte, m1, m2 *[32]byte) [32]byte {
	var b1, b2 [64]byte
	for i := 0; i < 32; i++ {
		b1[i] = adrs[i] ^ kPub[i]
		b1[32+i] = m1[i] ^ kPub[32+i]
	}
	v1 := areion.DM512(&b1)
	for i := 0; i < 32; i++ {
		b2[i] = v1[i] ^ kPub[i]
		b2[32+i] = m2[i] ^ adrs[i] ^ kPub[32+i]
	}
	b2[0] ^= 0x02
	return areion.DM512(&b2)
}

type avalancheStats struct {
	meanHW  float64
	minHW   float64
	maxHW   float64
	maxBias float64
	maxChi2 float64
}

func measureAvalanche(nSamples, inBits, outBytes int, evalFn func(in []byte, out []byte), rng *rand.Rand) avalancheStats {
	outBits := outBytes * 8
	bitFlips := make([][]int, inBits)
	for i := range bitFlips {
		bitFlips[i] = make([]int, outBits)
	}
	hist := make([][256]int, outBytes)
	inBytes := (inBits + 7) / 8
	inBuf := make([]byte, inBytes)
	inMod := make([]byte, inBytes)
	outBase := make([]byte, outBytes)
	outMod := make([]byte, outBytes)

	totalHD := 0
	for s := 0; s < nSamples; s++ {
		for i := range inBuf {
			inBuf[i] = byte(rng.Uint32())
		}
		evalFn(inBuf, outBase)
		for b := 0; b < outBytes; b++ {
			hist[b][outBase[b]]++
		}
		for ib := 0; ib < inBits; ib++ {
			copy(inMod, inBuf)
			inMod[ib/8] ^= 1 << (ib % 8)
			evalFn(inMod, outMod)
			for ob := 0; ob < outBytes; ob++ {
				diff := outBase[ob] ^ outMod[ob]
				totalHD += bits.OnesCount8(diff)
				for bit := 0; bit < 8; bit++ {
					if (diff>>bit)&1 != 0 {
						bitFlips[ib][8*ob+bit]++
					}
				}
			}
		}
	}

	meanHW := float64(totalHD) / float64(nSamples*inBits*outBits)
	minHW := 1.0
	maxHW := 0.0
	maxBias := 0.0
	for ib := 0; ib < inBits; ib++ {
		rowSum := 0
		for ob := 0; ob < outBits; ob++ {
			p := float64(bitFlips[ib][ob]) / float64(nSamples)
			rowSum += bitFlips[ib][ob]
			bias := math.Abs(p - 0.5)
			if bias > maxBias {
				maxBias = bias
			}
		}
		rowHW := float64(rowSum) / float64(nSamples*outBits)
		if rowHW < minHW {
			minHW = rowHW
		}
		if rowHW > maxHW {
			maxHW = rowHW
		}
	}

	expected := float64(nSamples) / 256.0
	maxChi2 := 0.0
	for b := 0; b < outBytes; b++ {
		chi2 := 0.0
		for v := 0; v < 256; v++ {
			d := float64(hist[b][v]) - expected
			chi2 += (d * d) / expected
		}
		if chi2 > maxChi2 {
			maxChi2 = chi2
		}
	}
	return avalancheStats{
		meanHW:  meanHW,
		minHW:   minHW,
		maxHW:   maxHW,
		maxBias: maxBias,
		maxChi2: maxChi2,
	}
}

func runSLHCollisionCheck(quick bool) {
	nSamples := 4096
	if quick {
		nSamples = 1024
	}
	rng := rand.New(rand.NewPCG(0x514D5A, 0xF195205))

	var pkSeed16, skSeed16 [16]byte
	var pkSeed32, skSeed32 [32]byte
	for i := 0; i < 16; i++ {
		pkSeed16[i] = byte(rng.Uint32())
		skSeed16[i] = byte(rng.Uint32())
	}
	for i := 0; i < 32; i++ {
		pkSeed32[i] = byte(rng.Uint32())
		skSeed32[i] = byte(rng.Uint32())
	}
	kPub128, _ := slhExpandSeed128Ref(&pkSeed16, &skSeed16)
	kPub256, kSK256 := slhExpandSeed256Ref(&pkSeed32, &skSeed32)

	// 1. Measure avalanche and byte uniformity across all 6 SLH-DSA-Areion primitives
	stF128 := measureAvalanche(nSamples, 384, 16, func(in, out []byte) {
		var adrs [32]byte
		var m1 [16]byte
		copy(adrs[:], in[0:32])
		copy(m1[:], in[32:48])
		res := slhF128Ref(&pkSeed16, &kPub128, &adrs, &m1)
		copy(out, res[:])
	}, rng)

	stF256 := measureAvalanche(nSamples, 512, 32, func(in, out []byte) {
		var adrs, m1 [32]byte
		copy(adrs[:], in[0:32])
		copy(m1[:], in[32:64])
		res := slhF256Ref(&kPub256, &adrs, &m1)
		copy(out, res[:])
	}, rng)

	stFTEM256 := measureAvalanche(nSamples, 512, 32, func(in, out []byte) {
		var adrs, m1 [32]byte
		copy(adrs[:], in[0:32])
		copy(m1[:], in[32:64])
		res := slhFTEM256Ref(&kPub256, &adrs, &m1)
		copy(out, res[:])
	}, rng)

	stH128 := measureAvalanche(nSamples, 384, 16, func(in, out []byte) {
		var adrs [32]byte
		var m1, m2 [16]byte
		// Map 16 bytes of compact ADRS back into active ADRS positions
		adrs[3] = in[0]
		copy(adrs[8:16], in[1:9])
		adrs[19] = in[9]
		copy(adrs[22:24], in[10:12])
		adrs[27] = in[12]
		copy(adrs[29:32], in[13:16])
		copy(m1[:], in[16:32])
		copy(m2[:], in[32:48])
		res := slhH128Ref(&pkSeed16, &kPub128, &adrs, &m1, &m2)
		copy(out, res[:])
	}, rng)

	stH256 := measureAvalanche(nSamples, 768, 32, func(in, out []byte) {
		var adrs, m1, m2 [32]byte
		copy(adrs[:], in[0:32])
		copy(m1[:], in[32:64])
		copy(m2[:], in[64:96])
		res := slhH256Ref(&kPub256, &adrs, &m1, &m2)
		copy(out, res[:])
	}, rng)

	stPRF256 := measureAvalanche(nSamples, 256, 32, func(in, out []byte) {
		var adrs [32]byte
		copy(adrs[:], in[0:32])
		res := slhPRF256Ref(&kSK256, &adrs)
		copy(out, res[:])
	}, rng)

	// 2. Empirical multi-target shift-attack verification (10,000 trials)
	nShift := 10000
	naiveCollisions := 0
	prof1Collisions := 0
	prof2Collisions := 0
	cat1Collisions := 0

	for t := 0; t < nShift; t++ {
		var adrs1, adrs2, m1 [32]byte
		for i := 0; i < 32; i++ {
			adrs1[i] = byte(rng.Uint32())
			adrs2[i] = byte(rng.Uint32())
			m1[i] = byte(rng.Uint32())
		}
		adrs2[0] ^= 0x01 // ensure distinct addresses ADRS1 != ADRS2

		// Compute public whitening masks W1 = P2(ADRS1 ^ K_pub2) ^ K_pub1 and W2 = P2(ADRS2 ^ K_pub2) ^ K_pub1
		var w1, w2 [32]byte
		for i := 0; i < 32; i++ {
			w1[i] = adrs1[i] ^ kPub256[32+i]
			w2[i] = adrs2[i] ^ kPub256[32+i]
		}
		areion.Permute256P2(&w1)
		areion.Permute256P2(&w2)
		var m1Shifted [32]byte
		for i := 0; i < 32; i++ {
			w1[i] ^= kPub256[i]
			w2[i] ^= kPub256[i]
			m1Shifted[i] = m1[i] ^ w1[i] ^ w2[i]
		}

		if slhFNaiveTEM256(&kPub256, &adrs1, &m1) == slhFNaiveTEM256(&kPub256, &adrs2, &m1Shifted) {
			naiveCollisions++
		}
		if slhF256Ref(&kPub256, &adrs1, &m1) == slhF256Ref(&kPub256, &adrs2, &m1Shifted) {
			prof1Collisions++
		}
		if slhFTEM256Ref(&kPub256, &adrs1, &m1) == slhFTEM256Ref(&kPub256, &adrs2, &m1Shifted) {
			prof2Collisions++
		}
		var m1_16, m1s_16 [16]byte
		copy(m1_16[:], m1[0:16])
		copy(m1s_16[:], m1Shifted[0:16])
		if slhF128Ref(&pkSeed16, &kPub128, &adrs1, &m1_16) == slhF128Ref(&pkSeed16, &kPub128, &adrs2, &m1s_16) {
			cat1Collisions++
		}
	}

	fmt.Println("=== Go Empirical SLH-DSA-Areion Avalanche & Shift-Collision Audit ===")
	fmt.Printf("Samples per primitive: %d\n", nSamples)
	fmt.Println("Primitive    InBits  OutBits  meanHW   minHW    maxHW    maxBias  maxChi2(255)")
	fmt.Println("-----------  ------  -------  -------  -------  -------  -------  ------------")
	rows := []struct {
		name string
		inB  int
		outB int
		st   avalancheStats
	}{
		{"SLHF128", 384, 128, stF128},
		{"SLHF256", 512, 256, stF256},
		{"SLHFTEM256", 512, 256, stFTEM256},
		{"SLHH128", 384, 128, stH128},
		{"SLHH256", 768, 256, stH256},
		{"SLHPRF256", 256, 256, stPRF256},
	}
	for _, r := range rows {
		fmt.Printf("%-11s  %6d  %7d  %.5f  %.5f  %.5f  %.5f  %12.2f\n",
			r.name, r.inB, r.outB, r.st.meanHW, r.st.minHW, r.st.maxHW, r.st.maxBias, r.st.maxChi2)
		if math.Abs(r.st.meanHW-0.5) > 0.005 || r.st.minHW < 0.485 || r.st.maxHW > 0.515 {
			panic(fmt.Sprintf("%s failed strict avalanche criterion", r.name))
		}
	}

	fmt.Println("--- Multi-Target Tweak-Shift Collision Test (M1' = M1 ^ W(ADRS) ^ W(ADRS')) ---")
	fmt.Printf("Naive TEM(K_pub, ADRS, M1) ^ M1 collisions:  %d / %d (100.0%% broken as predicted)\n", naiveCollisions, nShift)
	fmt.Printf("SLHF128 (Disjoint DM512) collisions:         %d / %d (0.0%%)\n", cat1Collisions, nShift)
	fmt.Printf("SLHF256 (Profile I DM512) collisions:        %d / %d (0.0%%)\n", prof1Collisions, nShift)
	fmt.Printf("SLHFTEM256 (Profile II MiddleTweak) colls:   %d / %d (0.0%%)\n", prof2Collisions, nShift)

	if naiveCollisions != nShift || cat1Collisions != 0 || prof1Collisions != 0 || prof2Collisions != 0 {
		panic("tweak-shift collision check failed")
	}
}
