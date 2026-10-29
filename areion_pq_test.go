package areionpq

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"encoding/hex"
	"runtime/debug"
	"testing"
)

var raceEnabled = func() bool {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "-race" && s.Value == "true" {
				return true
			}
		}
	}
	return false
}()

func TestVersionAndConstants(t *testing.T) {
	if Version != "0.2.0" || VersionMajor != 0 || VersionMinor != 2 || VersionPatch != 0 {
		t.Fatalf("unexpected version %s (%d.%d.%d)", Version, VersionMajor, VersionMinor, VersionPatch)
	}
	if BlockSize != 16 || State256Size != 32 || State512Size != 64 {
		t.Fatalf("unexpected block/state sizes: %d, %d, %d", BlockSize, State256Size, State512Size)
	}
	if Witness256Size != 288 || WitnessEM2_256Size != 576 {
		t.Fatalf("unexpected witness sizes: %d, %d", Witness256Size, WitnessEM2_256Size)
	}
	if FAEST128SeedSize != 32 || FAEST128PublicKeySize != 48 || FAEST128SecretKeySize != 64 {
		t.Fatalf("unexpected FAEST-128 key sizes")
	}
	if FAEST128sSigSize != 6448 || FAEST128fSigSize != 7456 {
		t.Fatalf("unexpected FAEST-128 sig sizes: %d, %d", FAEST128sSigSize, FAEST128fSigSize)
	}
	if FAEST256SeedSize != 64 || FAEST256PublicKeySize != 64 || FAEST256SecretKeySize != 96 {
		t.Fatalf("unexpected FAEST-256 key sizes")
	}
	if FAEST256sSigSize != 18208 || FAEST256fSigSize != 20512 {
		t.Fatalf("unexpected FAEST-256 sig sizes: %d, %d", FAEST256sSigSize, FAEST256fSigSize)
	}
	if FAESTEM2256SeedSize != 64 || FAESTEM2256PublicKeySize != 64 || FAESTEM2256SecretKeySize != 96 {
		t.Fatalf("unexpected FAEST-EM2-256 key sizes")
	}
	if FAESTEM2256sSigSize != 25696 || FAESTEM2256fSigSize != 30368 {
		t.Fatalf("unexpected FAEST-EM2-256 sig sizes: %d, %d", FAESTEM2256sSigSize, FAESTEM2256fSigSize)
	}
	if SLHDSA128SeedSize != 48 || SLHDSA128PublicKeySize != 32 || SLHDSA128SecretKeySize != 64 {
		t.Fatalf("unexpected SLH-DSA-128 key sizes")
	}
	if SLHDSA128fSigSize != 17088 || SLHDSA128sSigSize != 7856 {
		t.Fatalf("unexpected SLH-DSA-128 sig sizes: %d, %d", SLHDSA128fSigSize, SLHDSA128sSigSize)
	}
	if SLHDSA256SeedSize != 96 || SLHDSA256PublicKeySize != 64 || SLHDSA256SecretKeySize != 128 {
		t.Fatalf("unexpected SLH-DSA-256 key sizes")
	}
	if SLHDSA256fSigSize != 49856 || SLHDSA256sSigSize != 29792 {
		t.Fatalf("unexpected SLH-DSA-256 sig sizes: %d, %d", SLHDSA256fSigSize, SLHDSA256sSigSize)
	}
	if TEM2SIVKeySize != 128 || TEM2SIVNonceSize != 32 || TEM2SIVTagSize != 32 {
		t.Fatalf("unexpected TEM2-SIV sizes")
	}
}

func TestTierControlAndSelfTest(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	tiers := AvailableTiers()
	if len(tiers) == 0 || tiers[0] != "purego" {
		t.Fatalf("AvailableTiers() must include purego first, got %v", tiers)
	}

	if err := SetTier("nonexistent-tier"); err == nil {
		t.Fatal("expected error for unknown tier")
	}
	if err := SetTierCode(TierID(999)); err == nil {
		t.Fatal("expected error for unknown TierID")
	}

	for _, tier := range tiers {
		if err := SetTier(tier); err != nil {
			t.Fatalf("SetTier(%s): %v", tier, err)
		}
		if got := Tier(); got != tier {
			t.Fatalf("Tier() = %s, want %s", got, tier)
		}
		if err := SelfTest(); err != nil {
			t.Fatalf("[%s] SelfTest() failed: %v", tier, err)
		}
	}

	if err := SetTierCode(TierPureGo); err != nil || TierCode() != TierPureGo {
		t.Fatalf("SetTierCode(TierPureGo) failed: %v", err)
	}
	if err := SetTierCode(TierAuto); err != nil {
		t.Fatalf("SetTierCode(TierAuto) failed: %v", err)
	}

	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Zeroize(buf)
	for i, v := range buf {
		if v != 0 {
			t.Fatalf("Zeroize failed at byte %d: got %d", i, v)
		}
	}
}

func TestGF256FieldExhaustive(t *testing.T) {
	if GF256Inv(0) != 0 {
		t.Fatalf("GF256Inv(0) = %#x, want 0", GF256Inv(0))
	}
	if GF256Affine(0) != 0x63 {
		t.Fatalf("GF256Affine(0) = %#x, want 0x63", GF256Affine(0))
	}
	for a := 0; a < 256; a++ {
		ab := byte(a)
		sq := GF256Sq(ab)
		if sq != GF256Mul(ab, ab) {
			t.Fatalf("GF256Sq(%#x) = %#x != GF256Mul = %#x", ab, sq, GF256Mul(ab, ab))
		}
		aff := GF256Affine(ab)
		if got := GF256AffineInv(aff); got != ab {
			t.Fatalf("GF256AffineInv(GF256Affine(%#x)) = %#x", ab, got)
		}
		inv := GF256Inv(ab)
		if ab != 0 && GF256Mul(ab, inv) != 1 {
			t.Fatalf("GF256Mul(%#x, GF256Inv(%#x)=%#x) = %#x, want 1", ab, ab, inv, GF256Mul(ab, inv))
		}
		// S-box output s = Affine(Inv(a)); y = AffineInv(s) == Inv(a).
		// Must satisfy a^2 * y == a and y^2 * a == y for all a in 0..255.
		s := GF256Affine(inv)
		y := GF256AffineInv(s)
		if GF256Mul(GF256Sq(ab), y)^ab != 0 {
			t.Fatalf("degree-2 constraint 1 failed for a=%#x", ab)
		}
		if GF256Mul(GF256Sq(y), ab)^y != 0 {
			t.Fatalf("degree-2 constraint 2 failed for a=%#x", ab)
		}
	}
}

func TestGF128AndGF256CrossTier(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	var zero, one, x, a, b, c, chi [16]byte
	one[0] = 1
	x[0] = 2
	for i := 0; i < 16; i++ {
		a[i] = byte(0x13 + i*17)
		b[i] = byte(0x5B + i*29)
		c[i] = byte(0xA7 + i*11)
		chi[i] = byte(0x3D + i*7)
	}

	// Test x^127 * x == x^128 == 0x87 in GF(2^128)
	var x127, wantMod [16]byte
	x127[15] = 0x80
	wantMod[0] = 0x87

	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	if got := GF128Mul(&x127, &x); got != wantMod {
		t.Fatalf("x^127 * x = %x, want %x", got, wantMod)
	}
	if got := GF128Mul(&a, &zero); got != zero {
		t.Fatalf("a * 0 = %x, want 0", got)
	}
	if got := GF128Mul(&a, &one); got != a {
		t.Fatalf("a * 1 = %x, want %x", got, a)
	}
	// Distributivity: a * (b ^ c) == (a * b) ^ (a * c)
	var bc, abXorAC [16]byte
	for i := 0; i < 16; i++ {
		bc[i] = b[i] ^ c[i]
	}
	ab := GF128Mul(&a, &b)
	ac := GF128Mul(&a, &c)
	for i := 0; i < 16; i++ {
		abXorAC[i] = ab[i] ^ ac[i]
	}
	if got := GF128Mul(&a, &bc); got != abXorAC {
		t.Fatalf("distributivity failed: got %x, want %x", got, abXorAC)
	}

	vecA := make([][16]byte, 19)
	vecB := make([][16]byte, 19)
	for idx := range vecA {
		for j := 0; j < 16; j++ {
			vecA[idx][j] = byte(0x21 + idx*13 + j*5)
			vecB[idx][j] = byte(0x79 + idx*19 + j*3)
		}
	}
	refMul := GF128Mul(&a, &b)
	refMAC := GF128PolyMAC(vecA, vecB, &chi)

	var a256, b256 [32]byte
	copy(a256[0:16], a[:])
	copy(a256[16:32], c[:])
	copy(b256[0:16], b[:])
	copy(b256[16:32], chi[:])
	refMul256 := GF256FieldMul(&a256, &b256)
	refOrtho := MulOrtho256(&a256, &b256)
	refSigma := OrthoSigma256(&a256)

	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		if got := GF128Mul(&x127, &x); got != wantMod {
			t.Fatalf("[%s] x^127 * x = %x, want %x", tier, got, wantMod)
		}
		if got := GF128Mul(&a, &b); got != refMul {
			t.Fatalf("[%s] GF128Mul mismatch:\ngot  %x\nwant %x", tier, got, refMul)
		}
		if got := GF128PolyMAC(vecA, vecB, &chi); got != refMAC {
			t.Fatalf("[%s] GF128PolyMAC mismatch:\ngot  %x\nwant %x", tier, got, refMAC)
		}
		if got := GF256FieldMul(&a256, &b256); got != refMul256 {
			t.Fatalf("[%s] GF256FieldMul mismatch", tier)
		}
		if got := MulOrtho256(&a256, &b256); got != refOrtho {
			t.Fatalf("[%s] MulOrtho256 mismatch", tier)
		}
		if got := OrthoSigma256(&a256); got != refSigma {
			t.Fatalf("[%s] OrthoSigma256 mismatch", tier)
		}
	}
}

func TestWitnessExtractionAndVerificationCrossTier(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	var m, k1, k2 [32]byte
	for i := 0; i < 32; i++ {
		m[i] = byte(0x05 + i*3)
		k1[i] = byte(0x41 + i*7)
		k2[i] = byte(0x93 + i*11)
	}

	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	var refC1, refC2, refCEM2 [32]byte
	var refW1, refW2 [288]byte
	var refWEM2 [576]byte
	ExtractWitness256(&refC1, &refW1, &m, &k1, &k2)
	ExtractWitness256P2(&refC2, &refW2, &m, &k1, &k2)
	ExtractWitnessEM2_256(&refCEM2, &refWEM2, &m, &k1, &k2)

	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		var c1, c2, cEM2 [32]byte
		var w1, w2 [288]byte
		var wEM2 [576]byte
		ExtractWitness256(&c1, &w1, &m, &k1, &k2)
		if c1 != refC1 || w1 != refW1 {
			t.Fatalf("[%s] ExtractWitness256 mismatch with purego", tier)
		}
		if !VerifyWitness256(&m, &c1, &k1, &k2, &w1) {
			t.Fatalf("[%s] VerifyWitness256 rejected valid witness", tier)
		}

		ExtractWitness256P2(&c2, &w2, &m, &k1, &k2)
		if c2 != refC2 || w2 != refW2 {
			t.Fatalf("[%s] ExtractWitness256P2 mismatch with purego", tier)
		}
		if !VerifyWitness256P2(&m, &c2, &k1, &k2, &w2) {
			t.Fatalf("[%s] VerifyWitness256P2 rejected valid witness", tier)
		}

		ExtractWitnessEM2_256(&cEM2, &wEM2, &m, &k1, &k2)
		if cEM2 != refCEM2 || wEM2 != refWEM2 {
			t.Fatalf("[%s] ExtractWitnessEM2_256 mismatch with purego", tier)
		}
		if !VerifyWitnessEM2_256(&m, &cEM2, &k1, &k2, &wEM2) {
			t.Fatalf("[%s] VerifyWitnessEM2_256 rejected valid witness", tier)
		}

		// Tamper checks across all 288 witness bytes and c/m/k1/k2
		for idx := 0; idx < Witness256Size; idx += 19 {
			wBad := w1
			wBad[idx] ^= 0x01
			if VerifyWitness256(&m, &c1, &k1, &k2, &wBad) {
				t.Fatalf("[%s] VerifyWitness256 accepted tampered witness at byte %d", tier, idx)
			}
		}
		cBad := c1
		cBad[31] ^= 0x80
		if VerifyWitness256(&m, &cBad, &k1, &k2, &w1) {
			t.Fatalf("[%s] VerifyWitness256 accepted tampered ciphertext", tier)
		}
		for idx := 0; idx < WitnessEM2_256Size; idx += 37 {
			wEM2Bad := wEM2
			wEM2Bad[idx] ^= 0x04
			if VerifyWitnessEM2_256(&m, &cEM2, &k1, &k2, &wEM2Bad) {
				t.Fatalf("[%s] VerifyWitnessEM2_256 accepted tampered witness at byte %d", tier, idx)
			}
		}
	}
}

func TestFAESTSignaturesAllVariantsAndTamper(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	var seed128 [32]byte
	var opt128 [16]byte
	var seed256 [64]byte
	var opt256 [32]byte
	for i := range seed128 {
		seed128[i] = byte(i + 1)
	}
	for i := range opt128 {
		opt128[i] = byte(0xA0 + i)
	}
	for i := range seed256 {
		seed256[i] = byte(i + 1)
	}
	for i := range opt256 {
		opt256[i] = byte(0xB0 + i)
	}
	msg := []byte("FAEST-Areion post-quantum zero-knowledge signature test message")

	// 1. Cross-tier byte-for-byte parity on FAEST-128f and FAEST-256f
	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	refPK128f, refSK128f := FAESTKeygen128f(&seed128)
	refSig128f := FAESTSign128f(&refSK128f, msg, &opt128)
	if !FAESTVerify128f(&refPK128f, msg, &refSig128f) {
		t.Fatal("purego FAESTVerify128f failed on valid signature")
	}

	refPK256f, refSK256f := FAESTKeygen256f(&seed256)
	refSig256f := FAESTSign256f(&refSK256f, msg, &opt256)
	if !FAESTVerify256f(&refPK256f, msg, &refSig256f) {
		t.Fatal("purego FAESTVerify256f failed on valid signature")
	}

	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		pk128f, sk128f := FAESTKeygen128f(&seed128)
		sig128f := FAESTSign128f(&sk128f, msg, &opt128)
		if pk128f != refPK128f || sk128f != refSK128f || sig128f != refSig128f {
			t.Fatalf("[%s] FAEST-128f cross-tier parity mismatch", tier)
		}
		if !FAESTVerify128f(&pk128f, msg, &sig128f) {
			t.Fatalf("[%s] FAESTVerify128f failed", tier)
		}

		pk256f, sk256f := FAESTKeygen256f(&seed256)
		sig256f := FAESTSign256f(&sk256f, msg, &opt256)
		if pk256f != refPK256f || sk256f != refSK256f || sig256f != refSig256f {
			t.Fatalf("[%s] FAEST-256f cross-tier parity mismatch", tier)
		}
		if !FAESTVerify256f(&pk256f, msg, &sig256f) {
			t.Fatalf("[%s] FAESTVerify256f failed", tier)
		}
	}

	// Restore fastest tier for remaining variants and tamper tests
	_ = SetTier(orig)

	// 2. FAEST-128s roundtrip & tamper
	pk128s, sk128s := FAESTKeygen128s(&seed128)
	sig128s := FAESTSign128s(&sk128s, msg, &opt128)
	if !FAESTVerify128s(&pk128s, msg, &sig128s) {
		t.Fatal("FAESTVerify128s failed on valid signature")
	}
	for _, off := range []int{0, 32, 200, 1000, 4500, FAEST128sSigSize - 1} {
		bad := sig128s
		bad[off] ^= 0x01
		if FAESTVerify128s(&pk128s, msg, &bad) {
			t.Fatalf("FAESTVerify128s accepted tampered signature at offset %d", off)
		}
	}
	if FAESTVerify128s(&pk128s, []byte("tampered"), &sig128s) {
		t.Fatal("FAESTVerify128s accepted tampered message")
	}
	badPK128 := pk128s
	badPK128[20] ^= 0x01
	if FAESTVerify128s(&badPK128, msg, &sig128s) {
		t.Fatal("FAESTVerify128s accepted tampered public key")
	}

	// 3. FAEST-128f tamper
	for _, off := range []int{0, 32, 300, 2000, 5500, FAEST128fSigSize - 1} {
		bad := refSig128f
		bad[off] ^= 0x01
		if FAESTVerify128f(&refPK128f, msg, &bad) {
			t.Fatalf("FAESTVerify128f accepted tampered signature at offset %d", off)
		}
	}

	// 4. FAEST-256s roundtrip & tamper
	pk256s, sk256s := FAESTKeygen256s(&seed256)
	sig256s := FAESTSign256s(&sk256s, msg, &opt256)
	if !FAESTVerify256s(&pk256s, msg, &sig256s) {
		t.Fatal("FAESTVerify256s failed on valid signature")
	}
	for _, off := range []int{0, 32, 360, 5000, 12000, FAEST256sSigSize - 1} {
		bad := sig256s
		bad[off] ^= 0x01
		if FAESTVerify256s(&pk256s, msg, &bad) {
			t.Fatalf("FAESTVerify256s accepted tampered signature at offset %d", off)
		}
	}

	// 5. FAEST-EM2-256f and FAEST-EM2-256s roundtrip & tamper
	pkEM2f, skEM2f := FAESTEM2Keygen256f(&seed256)
	sigEM2f := FAESTEM2Sign256f(&skEM2f, msg, &opt256)
	if !FAESTEM2Verify256f(&pkEM2f, msg, &sigEM2f) {
		t.Fatal("FAESTEM2Verify256f failed on valid signature")
	}
	for _, off := range []int{0, 32, 400, 8000, 22000, FAESTEM2256fSigSize - 1} {
		bad := sigEM2f
		bad[off] ^= 0x01
		if FAESTEM2Verify256f(&pkEM2f, msg, &bad) {
			t.Fatalf("FAESTEM2Verify256f accepted tampered signature at offset %d", off)
		}
	}

	pkEM2s, skEM2s := FAESTEM2Keygen256s(&seed256)
	sigEM2s := FAESTEM2Sign256s(&skEM2s, msg, &opt256)
	if !FAESTEM2Verify256s(&pkEM2s, msg, &sigEM2s) {
		t.Fatal("FAESTEM2Verify256s failed on valid signature")
	}
	for _, off := range []int{0, 32, 500, 10000, FAESTEM2256sSigSize - 1} {
		bad := sigEM2s
		bad[off] ^= 0x01
		if FAESTEM2Verify256s(&pkEM2s, msg, &bad) {
			t.Fatalf("FAESTEM2Verify256s accepted tampered signature at offset %d", off)
		}
	}
}

func TestSLHDSATweakableHashesAndSignatures(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	var pkSeed16, skSeed16, m1_16, m2_16 [16]byte
	var pkSeed32, skSeed32, adrs, m1_32, m2_32 [32]byte
	for i := 0; i < 16; i++ {
		pkSeed16[i] = byte(0x11 + i)
		skSeed16[i] = byte(0x31 + i)
		m1_16[i] = byte(0x51 + i)
		m2_16[i] = byte(0x71 + i)
	}
	for i := 0; i < 32; i++ {
		pkSeed32[i] = byte(0x11 + i)
		skSeed32[i] = byte(0x41 + i)
		adrs[i] = byte(i)
		m1_32[i] = byte(0x81 + i)
		m2_32[i] = byte(0xB1 + i)
	}

	var adrs4 [4][32]byte
	for l := 0; l < 4; l++ {
		adrs4[l] = adrs
		adrs4[l][31] = byte(l)
	}

	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	refKPub128, refKSK128 := SLHExpandSeed128(&pkSeed16, &skSeed16)
	refKPub256, refKSK256 := SLHExpandSeed256(&pkSeed32, &skSeed32)
	refF128 := SLHF128(&pkSeed16, &refKPub128, &adrs, &m1_16)
	refF256 := SLHF256(&refKPub256, &adrs, &m1_32)
	refFTEM256 := SLHFTEM256(&refKPub256, &adrs, &m1_32)
	refH128 := SLHH128(&pkSeed16, &refKPub128, &adrs, &m1_16, &m2_16)
	refH256 := SLHH256(&refKPub256, &adrs, &m1_32, &m2_32)
	refTl128 := SLHTl128(&refKPub128, &adrs, [][16]byte{m1_16, m2_16, pkSeed16})
	refTl256 := SLHTl256(&refKPub256, &adrs, [][32]byte{m1_32, m2_32, pkSeed32})

	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		kPub128, kSK128 := SLHExpandSeed128(&pkSeed16, &skSeed16)
		kPub256, kSK256 := SLHExpandSeed256(&pkSeed32, &skSeed32)
		if kPub128 != refKPub128 || kSK128 != refKSK128 || kPub256 != refKPub256 || kSK256 != refKSK256 {
			t.Fatalf("[%s] SLHExpandSeed mismatch", tier)
		}
		prf4 := SLHPRF256x4(&kSK256, &adrs4)
		for l := 0; l < 4; l++ {
			if single := SLHPRF256(&kSK256, &adrs4[l]); prf4[l] != single {
				t.Fatalf("[%s] SLHPRF256x4 lane %d mismatch", tier, l)
			}
		}
		if SLHF128(&pkSeed16, &kPub128, &adrs, &m1_16) != refF128 {
			t.Fatalf("[%s] SLHF128 mismatch", tier)
		}
		if SLHF256(&kPub256, &adrs, &m1_32) != refF256 {
			t.Fatalf("[%s] SLHF256 mismatch", tier)
		}
		if SLHFTEM256(&kPub256, &adrs, &m1_32) != refFTEM256 {
			t.Fatalf("[%s] SLHFTEM256 mismatch", tier)
		}
		if SLHH128(&pkSeed16, &kPub128, &adrs, &m1_16, &m2_16) != refH128 {
			t.Fatalf("[%s] SLHH128 mismatch", tier)
		}
		if SLHH256(&kPub256, &adrs, &m1_32, &m2_32) != refH256 {
			t.Fatalf("[%s] SLHH256 mismatch", tier)
		}
		if SLHTl128(&kPub128, &adrs, [][16]byte{m1_16, m2_16, pkSeed16}) != refTl128 {
			t.Fatalf("[%s] SLHTl128 mismatch", tier)
		}
		if SLHTl256(&kPub256, &adrs, [][32]byte{m1_32, m2_32, pkSeed32}) != refTl256 {
			t.Fatalf("[%s] SLHTl256 mismatch", tier)
		}
	}

	var seed48 [48]byte
	var opt16 [16]byte
	var seed96 [96]byte
	var opt32 [32]byte
	for i := range seed48 {
		seed48[i] = byte(i + 1)
	}
	for i := range opt16 {
		opt16[i] = byte(0xC0 + i)
	}
	for i := range seed96 {
		seed96[i] = byte(i + 1)
	}
	for i := range opt32 {
		opt32[i] = byte(0xD0 + i)
	}
	msg := []byte("SLH-DSA-Areion FIPS 205 stateless hash-based signature test message")

	// Cross-tier parity on SLH-DSA-128f and SLH-DSA-256f
	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	refPK128f, refSK128f := SLHDSAKeygen128f(&seed48)
	refSig128f := SLHDSASign128f(&refSK128f, msg, &opt16)
	if !SLHDSAVerify128f(&refPK128f, msg, &refSig128f) {
		t.Fatal("purego SLHDSAVerify128f failed")
	}

	refPK256f, refSK256f := SLHDSAKeygen256f(&seed96)
	refSig256f := SLHDSASign256f(&refSK256f, msg, &opt32)
	if !SLHDSAVerify256f(&refPK256f, msg, &refSig256f) {
		t.Fatal("purego SLHDSAVerify256f failed")
	}

	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		pk128f, sk128f := SLHDSAKeygen128f(&seed48)
		sig128f := SLHDSASign128f(&sk128f, msg, &opt16)
		if pk128f != refPK128f || sk128f != refSK128f || sig128f != refSig128f {
			t.Fatalf("[%s] SLH-DSA-128f cross-tier parity mismatch", tier)
		}
		if !SLHDSAVerify128f(&pk128f, msg, &sig128f) {
			t.Fatalf("[%s] SLHDSAVerify128f failed", tier)
		}

		pk256f, sk256f := SLHDSAKeygen256f(&seed96)
		sig256f := SLHDSASign256f(&sk256f, msg, &opt32)
		if pk256f != refPK256f || sk256f != refSK256f || sig256f != refSig256f {
			t.Fatalf("[%s] SLH-DSA-256f cross-tier parity mismatch", tier)
		}
		if !SLHDSAVerify256f(&pk256f, msg, &sig256f) {
			t.Fatalf("[%s] SLHDSAVerify256f failed", tier)
		}
	}

	_ = SetTier(orig)

	// Tamper checks on 128f and 256f
	for _, off := range []int{0, 16, 1000, 8000, SLHDSA128fSigSize - 1} {
		bad := refSig128f
		bad[off] ^= 0x01
		if SLHDSAVerify128f(&refPK128f, msg, &bad) {
			t.Fatalf("SLHDSAVerify128f accepted tampered signature at offset %d", off)
		}
	}
	if SLHDSAVerify128f(&refPK128f, []byte("wrong"), &refSig128f) {
		t.Fatal("SLHDSAVerify128f accepted wrong message")
	}

	// SLH-DSA-TEM-256f roundtrip & tamper
	pkTEM, skTEM := SLHDSATEMKeygen256f(&seed96)
	sigTEM := SLHDSATEMSign256f(&skTEM, msg, &opt32)
	if !SLHDSATEMVerify256f(&pkTEM, msg, &sigTEM) {
		t.Fatal("SLHDSATEMVerify256f failed on valid signature")
	}
	for _, off := range []int{0, 32, 4000, 25000, SLHDSA256fSigSize - 1} {
		bad := sigTEM
		bad[off] ^= 0x01
		if SLHDSATEMVerify256f(&pkTEM, msg, &bad) {
			t.Fatalf("SLHDSATEMVerify256f accepted tampered signature at offset %d", off)
		}
	}

	// SLH-DSA-128s and SLH-DSA-256s roundtrip & tamper
	pk128s, sk128s := SLHDSAKeygen128s(&seed48)
	sig128s := SLHDSASign128s(&sk128s, msg, &opt16)
	if !SLHDSAVerify128s(&pk128s, msg, &sig128s) {
		t.Fatal("SLHDSAVerify128s failed on valid signature")
	}
	bad128s := sig128s
	bad128s[500] ^= 0x01
	if SLHDSAVerify128s(&pk128s, msg, &bad128s) {
		t.Fatal("SLHDSAVerify128s accepted tampered signature")
	}

	pk256s, sk256s := SLHDSAKeygen256s(&seed96)
	sig256s := SLHDSASign256s(&sk256s, msg, &opt32)
	if !SLHDSAVerify256s(&pk256s, msg, &sig256s) {
		t.Fatal("SLHDSAVerify256s failed on valid signature")
	}
	bad256s := sig256s
	bad256s[1500] ^= 0x01
	if SLHDSAVerify256s(&pk256s, msg, &bad256s) {
		t.Fatal("SLHDSAVerify256s accepted tampered signature")
	}
}

func TestKDFTEM2SIVAndHPKE(t *testing.T) {
	orig := Tier()
	defer func() { _ = SetTier(orig) }()

	secret := []byte("areion-pq-kdf-master-secret-material")
	context := []byte("areion-pq-kdf-context-info")

	if err := SetTier("purego"); err != nil {
		t.Fatal(err)
	}
	refKDF := make([]byte, 320)
	KDFExpand(secret, context, refKDF)

	var key [128]byte
	var nonce [32]byte
	var shared [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
		shared[i] = byte(0x80 + i)
	}

	lengths := []int{0, 1, 15, 32, 63, 64, 65, 128, 255, 256, 257, 519}
	for _, tier := range AvailableTiers() {
		if err := SetTier(tier); err != nil {
			t.Fatal(err)
		}
		gotKDF := make([]byte, 320)
		KDFExpand(secret, context, gotKDF)
		if !bytes.Equal(gotKDF, refKDF) {
			t.Fatalf("[%s] KDFExpand mismatch with purego:\ngot  %s\nwant %s", tier, hex.EncodeToString(gotKDF[:32]), hex.EncodeToString(refKDF[:32]))
		}
		// Prefix consistency check
		shortKDF := make([]byte, 96)
		KDFExpand(secret, context, shortKDF)
		if !bytes.Equal(shortKDF, refKDF[:96]) {
			t.Fatalf("[%s] KDFExpand prefix mismatch", tier)
		}

		for _, ptLen := range lengths {
			pt := make([]byte, ptLen)
			for i := range pt {
				pt[i] = byte(0x31 + i*7)
			}
			ad := []byte("authenticated-additional-data-header")

			ct, tag := TEM2SIVEncrypt(&key, &nonce, ad, pt)
			dec, ok := TEM2SIVDecrypt(&key, &nonce, ad, ct, &tag)
			if !ok || !bytes.Equal(dec, pt) {
				t.Fatalf("[%s] TEM2SIV roundtrip failed for len=%d", tier, ptLen)
			}

			// Tamper tag
			badTag := tag
			badTag[0] ^= 0x01
			if decBad, ok := TEM2SIVDecrypt(&key, &nonce, ad, ct, &badTag); ok || decBad != nil {
				t.Fatalf("[%s] TEM2SIV accepted tampered tag for len=%d", tier, ptLen)
			}

			// Tamper AD
			if _, ok := TEM2SIVDecrypt(&key, &nonce, []byte("wrong-ad"), ct, &tag); ok {
				t.Fatalf("[%s] TEM2SIV accepted tampered AD for len=%d", tier, ptLen)
			}

			// Tamper ciphertext and verify in-place zeroization on failure
			if ptLen > 0 {
				badCT := append([]byte(nil), ct...)
				badCT[ptLen/2] ^= 0x80
				dstBuf := make([]byte, ptLen)
				for i := range dstBuf {
					dstBuf[i] = 0xAA
				}
				if TEM2SIVDecryptInPlace(&key, &nonce, ad, dstBuf, badCT, &tag) {
					t.Fatalf("[%s] TEM2SIVDecryptInPlace accepted tampered ciphertext for len=%d", tier, ptLen)
				}
				for i, b := range dstBuf {
					if b != 0 {
						t.Fatalf("[%s] TEM2SIVDecryptInPlace did not zeroize output at byte %d on auth failure", tier, i)
					}
				}
			}

			// HPKE deterministic seal/open
			hpkeCT, hpkeTag := HPKESealDet(&shared, context, 42, ad, pt)
			hpkePT, ok := HPKEOpenDet(&shared, context, 42, ad, hpkeCT, &hpkeTag)
			if !ok || !bytes.Equal(hpkePT, pt) {
				t.Fatalf("[%s] HPKESealDet/OpenDet roundtrip failed for len=%d", tier, ptLen)
			}
			if _, ok := HPKEOpenDet(&shared, context, 43, ad, hpkeCT, &hpkeTag); ok {
				t.Fatalf("[%s] HPKEOpenDet accepted wrong sequence number", tier)
			}
		}
	}
}

func TestCryptoSignerAndMLKEM768(t *testing.T) {
	// 1. ML-KEM-768 + Areion-HPKE roundtrip & tamper rejection
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey768: %v", err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	info := []byte("areion-pq-mlkem768-hpke-info")
	ad := []byte("areion-pq-mlkem768-hpke-ad")
	pt := []byte("post-quantum hybrid public-key encryption payload")

	kemCT, ct, tag, err := HPKESealMLKEM768(ekBytes, info, ad, pt)
	if err != nil {
		t.Fatalf("HPKESealMLKEM768: %v", err)
	}
	dec, err := HPKEOpenMLKEM768(dk, kemCT, info, ad, ct, &tag)
	if err != nil || !bytes.Equal(dec, pt) {
		t.Fatalf("HPKEOpenMLKEM768 roundtrip failed: err=%v", err)
	}
	badTag := tag
	badTag[0] ^= 0x01
	if _, err := HPKEOpenMLKEM768(dk, kemCT, info, ad, ct, &badTag); err == nil {
		t.Fatal("HPKEOpenMLKEM768 accepted tampered tag")
	}
	if _, err := HPKEOpenMLKEM768(nil, kemCT, info, ad, ct, &tag); err == nil {
		t.Fatal("HPKEOpenMLKEM768 accepted nil decapsulation key")
	}

	// 2. FAESTPrivateKey / FAESTPublicKey crypto.Signer interface
	var fSeed [32]byte
	for i := range fSeed {
		fSeed[i] = byte(0x11 + i)
	}
	fPK, fSK := FAESTKeygen128f(&fSeed)
	faestSigner := &FAESTPrivateKey{
		Variant: "128f",
		Bytes:   fSK[:],
		Pub: FAESTPublicKey{
			Variant: "128f",
			Bytes:   fPK[:],
		},
	}
	var _ crypto.Signer = faestSigner
	if !faestSigner.Pub.Equal(faestSigner.Public()) {
		t.Fatal("FAESTPublicKey.Equal failed on identical key")
	}
	msg := []byte("crypto.Signer test message")
	fSig, err := faestSigner.Sign(bytes.NewReader(make([]byte, 32)), msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("FAESTPrivateKey.Sign: %v", err)
	}
	if !faestSigner.Pub.Verify(msg, fSig) {
		t.Fatal("FAESTPublicKey.Verify failed on valid signature")
	}
	fSig[0] ^= 0x01
	if faestSigner.Pub.Verify(msg, fSig) {
		t.Fatal("FAESTPublicKey.Verify accepted tampered signature")
	}

	// 3. SLHDSAPrivateKey / SLHDSAPublicKey crypto.Signer interface
	var sSeed [48]byte
	for i := range sSeed {
		sSeed[i] = byte(0x21 + i)
	}
	sPK, sSK := SLHDSAKeygen128f(&sSeed)
	slhSigner := &SLHDSAPrivateKey{
		Variant: "128f",
		Bytes:   sSK[:],
		Pub: SLHDSAPublicKey{
			Variant: "128f",
			Bytes:   sPK[:],
		},
	}
	var _ crypto.Signer = slhSigner
	if !slhSigner.Pub.Equal(slhSigner.Public()) {
		t.Fatal("SLHDSAPublicKey.Equal failed on identical key")
	}
	sSig, err := slhSigner.Sign(bytes.NewReader(make([]byte, 32)), msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("SLHDSAPrivateKey.Sign: %v", err)
	}
	if !slhSigner.Pub.Verify(msg, sSig) {
		t.Fatal("SLHDSAPublicKey.Verify failed on valid signature")
	}
	sSig[0] ^= 0x01
	if slhSigner.Pub.Verify(msg, sSig) {
		t.Fatal("SLHDSAPublicKey.Verify accepted tampered signature")
	}
}

func BenchmarkGF128Mul(b *testing.B) {
	var out, x, y [16]byte
	x[0] = 0x53
	y[0] = 0xCA
	b.SetBytes(16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = GF128Mul(&x, &y)
	}
	_ = out
}

func BenchmarkGF128PolyMAC16(b *testing.B) {
	a := make([][16]byte, 16)
	y := make([][16]byte, 16)
	var chi [16]byte
	chi[0] = 0x19
	b.SetBytes(16 * 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GF128PolyMAC(a, y, &chi)
	}
}

func BenchmarkExtractWitness256(b *testing.B) {
	var c, m, k1, k2 [32]byte
	var w [288]byte
	b.SetBytes(288)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractWitness256(&c, &w, &m, &k1, &k2)
	}
}

func BenchmarkVerifyWitness256(b *testing.B) {
	var c, m, k1, k2 [32]byte
	var w [288]byte
	ExtractWitness256(&c, &w, &m, &k1, &k2)
	b.SetBytes(288)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyWitness256(&m, &c, &k1, &k2, &w) {
			b.Fatal("VerifyWitness256 failed")
		}
	}
}

func BenchmarkExtractWitnessEM2_256(b *testing.B) {
	var c, m, k1, k2 [32]byte
	var w [576]byte
	b.SetBytes(576)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractWitnessEM2_256(&c, &w, &m, &k1, &k2)
	}
}

func BenchmarkVerifyWitnessEM2_256(b *testing.B) {
	var c, m, k1, k2 [32]byte
	var w [576]byte
	ExtractWitnessEM2_256(&c, &w, &m, &k1, &k2)
	b.SetBytes(576)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyWitnessEM2_256(&m, &c, &k1, &k2, &w) {
			b.Fatal("VerifyWitnessEM2_256 failed")
		}
	}
}

func BenchmarkFAESTSign128f(b *testing.B) {
	var seed [32]byte
	var opt [16]byte
	var msg [32]byte
	_, sk := FAESTKeygen128f(&seed)
	b.SetBytes(FAEST128fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FAESTSign128f(&sk, msg[:], &opt)
	}
}

func BenchmarkFAESTVerify128f(b *testing.B) {
	var seed [32]byte
	var opt [16]byte
	var msg [32]byte
	pk, sk := FAESTKeygen128f(&seed)
	sig := FAESTSign128f(&sk, msg[:], &opt)
	b.SetBytes(FAEST128fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !FAESTVerify128f(&pk, msg[:], &sig) {
			b.Fatal("FAESTVerify128f failed")
		}
	}
}

func BenchmarkFAESTSign256f(b *testing.B) {
	var seed [64]byte
	var opt [32]byte
	var msg [32]byte
	_, sk := FAESTKeygen256f(&seed)
	b.SetBytes(FAEST256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FAESTSign256f(&sk, msg[:], &opt)
	}
}

func BenchmarkFAESTVerify256f(b *testing.B) {
	var seed [64]byte
	var opt [32]byte
	var msg [32]byte
	pk, sk := FAESTKeygen256f(&seed)
	sig := FAESTSign256f(&sk, msg[:], &opt)
	b.SetBytes(FAEST256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !FAESTVerify256f(&pk, msg[:], &sig) {
			b.Fatal("FAESTVerify256f failed")
		}
	}
}

func BenchmarkFAESTEM2Sign256f(b *testing.B) {
	var seed [64]byte
	var opt [32]byte
	var msg [32]byte
	_, sk := FAESTEM2Keygen256f(&seed)
	b.SetBytes(FAESTEM2256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FAESTEM2Sign256f(&sk, msg[:], &opt)
	}
}

func BenchmarkFAESTEM2Verify256f(b *testing.B) {
	var seed [64]byte
	var opt [32]byte
	var msg [32]byte
	pk, sk := FAESTEM2Keygen256f(&seed)
	sig := FAESTEM2Sign256f(&sk, msg[:], &opt)
	b.SetBytes(FAESTEM2256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !FAESTEM2Verify256f(&pk, msg[:], &sig) {
			b.Fatal("FAESTEM2Verify256f failed")
		}
	}
}

func BenchmarkSLHDSASign128f(b *testing.B) {
	var seed [48]byte
	var opt [16]byte
	var msg [32]byte
	_, sk := SLHDSAKeygen128f(&seed)
	b.SetBytes(SLHDSA128fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SLHDSASign128f(&sk, msg[:], &opt)
	}
}

func BenchmarkSLHDSAVerify128f(b *testing.B) {
	var seed [48]byte
	var opt [16]byte
	var msg [32]byte
	pk, sk := SLHDSAKeygen128f(&seed)
	sig := SLHDSASign128f(&sk, msg[:], &opt)
	b.SetBytes(SLHDSA128fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !SLHDSAVerify128f(&pk, msg[:], &sig) {
			b.Fatal("SLHDSAVerify128f failed")
		}
	}
}

func BenchmarkSLHDSASign256f(b *testing.B) {
	var seed [96]byte
	var opt [32]byte
	var msg [32]byte
	_, sk := SLHDSAKeygen256f(&seed)
	b.SetBytes(SLHDSA256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SLHDSASign256f(&sk, msg[:], &opt)
	}
}

func BenchmarkSLHDSAVerify256f(b *testing.B) {
	var seed [96]byte
	var opt [32]byte
	var msg [32]byte
	pk, sk := SLHDSAKeygen256f(&seed)
	sig := SLHDSASign256f(&sk, msg[:], &opt)
	b.SetBytes(SLHDSA256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !SLHDSAVerify256f(&pk, msg[:], &sig) {
			b.Fatal("SLHDSAVerify256f failed")
		}
	}
}

func BenchmarkSLHDSATEMSign256f(b *testing.B) {
	var seed [96]byte
	var opt [32]byte
	var msg [32]byte
	_, sk := SLHDSATEMKeygen256f(&seed)
	b.SetBytes(SLHDSA256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = SLHDSATEMSign256f(&sk, msg[:], &opt)
	}
}

func BenchmarkSLHDSATEMVerify256f(b *testing.B) {
	var seed [96]byte
	var opt [32]byte
	var msg [32]byte
	pk, sk := SLHDSATEMKeygen256f(&seed)
	sig := SLHDSATEMSign256f(&sk, msg[:], &opt)
	b.SetBytes(SLHDSA256fSigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !SLHDSATEMVerify256f(&pk, msg[:], &sig) {
			b.Fatal("SLHDSATEMVerify256f failed")
		}
	}
}

func BenchmarkAreionKDF1KB(b *testing.B) {
	var secret, ctx [32]byte
	var out [1024]byte
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KDFExpand(secret[:], ctx[:], out[:])
	}
}

func BenchmarkTEM2SIVEncrypt4KB(b *testing.B) {
	var key [128]byte
	var nonce [32]byte
	var ad [64]byte
	var pt, ct [4096]byte
	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TEM2SIVEncryptInPlace(&key, &nonce, ad[:], ct[:], pt[:])
	}
}

func BenchmarkTEM2SIVDecrypt4KB(b *testing.B) {
	var key [128]byte
	var nonce [32]byte
	var ad [64]byte
	var pt, ct, dec [4096]byte
	tag := TEM2SIVEncryptInPlace(&key, &nonce, ad[:], ct[:], pt[:])
	b.SetBytes(4096)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !TEM2SIVDecryptInPlace(&key, &nonce, ad[:], dec[:], ct[:], &tag) {
			b.Fatal("TEM2SIVDecryptInPlace failed")
		}
	}
}
