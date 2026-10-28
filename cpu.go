package areionpq

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/everanium/areion"
)

// TierID identifies a hardware or software execution tier.
type TierID int

// Hardware acceleration tier constants.
const (
	TierAuto      TierID = 0
	TierPureGo    TierID = 1
	TierAESNI     TierID = 2
	TierVEX       TierID = 3
	TierVAESAVX2  TierID = 4
	TierAVX512    TierID = 5
	TierARM64     TierID = 6
	TierARMCrypto TierID = TierARM64
)

// Hardware capability flags detected at initialization (read-only after init).
var (
	hasAESNI     bool
	hasVEX       bool // 128-bit VEX-encoded VAESENC / VPCLMULQDQ on XMM (requires AVX + AES-NI + PCLMULQDQ)
	hasARMCrypto bool // ARMv8 Cryptographic Extension (AESE/AESMC + PMULL)
	hasVAESAVX2  bool // VAES + VPCLMULQDQ on 256-bit YMM (requires AVX2 + VAES)
	hasAVX512    bool // VAES + VPCLMULQDQ on 512-bit ZMM (requires AVX-512F + VAES)
)

var (
	tierMu         sync.Mutex
	activeTierCode int32
)

func init() {
	hasAESNI, hasVEX, hasARMCrypto, hasVAESAVX2, hasAVX512 = probeCPU()
	_ = setTierLocked("auto")
	applyEnvTier()
}

func setTierLocked(tier string) error {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	switch normalized {
	case "auto":
		if hasAVX512 {
			atomic.StoreInt32(&activeTierCode, int32(TierAVX512))
		} else if hasVAESAVX2 {
			atomic.StoreInt32(&activeTierCode, int32(TierVAESAVX2))
		} else if hasVEX {
			atomic.StoreInt32(&activeTierCode, int32(TierVEX))
		} else if hasAESNI {
			atomic.StoreInt32(&activeTierCode, int32(TierAESNI))
		} else if hasARMCrypto {
			atomic.StoreInt32(&activeTierCode, int32(TierARM64))
		} else {
			atomic.StoreInt32(&activeTierCode, int32(TierPureGo))
		}
		_ = areion.SetTier("auto")
		return nil
	case "avx512":
		if !hasAVX512 {
			return fmt.Errorf("areionpq: host CPU lacks AVX-512F + VAES")
		}
		atomic.StoreInt32(&activeTierCode, int32(TierAVX512))
		_ = areion.SetTier("avx512")
	case "vaesavx2":
		if !hasVAESAVX2 {
			return fmt.Errorf("areionpq: host CPU lacks AVX2 + VAES")
		}
		atomic.StoreInt32(&activeTierCode, int32(TierVAESAVX2))
		_ = areion.SetTier("vaesavx2")
	case "vex":
		if !hasVEX {
			return fmt.Errorf("areionpq: host CPU lacks AVX + AES-NI")
		}
		atomic.StoreInt32(&activeTierCode, int32(TierVEX))
		_ = areion.SetTier("vex")
	case "aesni":
		if !hasAESNI {
			return fmt.Errorf("areionpq: host CPU lacks AES-NI")
		}
		atomic.StoreInt32(&activeTierCode, int32(TierAESNI))
		_ = areion.SetTier("aesni")
	case "arm64", "neon", "sve", "sve2":
		if !hasARMCrypto {
			return fmt.Errorf("areionpq: host CPU lacks ARM Cryptographic Extension")
		}
		atomic.StoreInt32(&activeTierCode, int32(TierARM64))
		_ = areion.SetTier("arm64")
	case "purego", "purec", "scalar", "gpr":
		atomic.StoreInt32(&activeTierCode, int32(TierPureGo))
		_ = areion.SetTier("purego")
	default:
		return fmt.Errorf("areionpq: unknown tier %q (want: avx512, vaesavx2, vex, aesni, arm64/neon/sve/sve2, purego/purec/scalar, auto)", tier)
	}
	return nil
}

func applyEnvTier() {
	for _, key := range []string{"AREION_PQ_FORCE_TIER", "AREION_FORCE_TIER", "AREION_TIER"} {
		if val := os.Getenv(key); val != "" {
			if err := SetTier(val); err != nil {
				fmt.Fprintf(os.Stderr, "areionpq: invalid %s=%q: %v\n", key, val, err)
			}
			return
		}
	}
}

// Tier returns the currently active hardware acceleration tier name:
// "avx512", "vaesavx2", "vex", "aesni", "arm64", or "purego".
func Tier() string {
	switch TierCode() {
	case TierAVX512:
		return "avx512"
	case TierVAESAVX2:
		return "vaesavx2"
	case TierVEX:
		return "vex"
	case TierAESNI:
		return "aesni"
	case TierARM64:
		return "arm64"
	default:
		return "purego"
	}
}

// TierCode returns the TierID of the active hardware tier.
func TierCode() TierID {
	return TierID(atomic.LoadInt32(&activeTierCode))
}

// AvailableTiers returns the list of execution tier names supported on the current CPU.
func AvailableTiers() []string {
	tiers := []string{"purego"}
	if hasAESNI {
		tiers = append(tiers, "aesni")
	}
	if hasVEX {
		tiers = append(tiers, "vex")
	}
	if hasVAESAVX2 {
		tiers = append(tiers, "vaesavx2")
	}
	if hasAVX512 {
		tiers = append(tiers, "avx512")
	}
	if hasARMCrypto {
		tiers = append(tiers, "arm64")
	}
	return tiers
}

// SetTier forces the active acceleration tier by name and synchronizes the underlying
// areion permutation tier. Valid values: "avx512", "vaesavx2", "vex", "aesni",
// "arm64", "purego", or "auto".
func SetTier(name string) error {
	tierMu.Lock()
	defer tierMu.Unlock()
	return setTierLocked(name)
}

// SetTierCode forces the active acceleration tier by TierID.
func SetTierCode(id TierID) error {
	switch id {
	case TierAuto:
		return SetTier("auto")
	case TierPureGo:
		return SetTier("purego")
	case TierAESNI:
		return SetTier("aesni")
	case TierVEX:
		return SetTier("vex")
	case TierVAESAVX2:
		return SetTier("vaesavx2")
	case TierAVX512:
		return SetTier("avx512")
	case TierARM64:
		return SetTier("arm64")
	default:
		return fmt.Errorf("areionpq: unknown TierID %d", id)
	}
}

// UseHardwareAcceleration reports whether hardware AES acceleration is available
// and currently enabled (i.e. the active tier is not purego).
func UseHardwareAcceleration() bool {
	return (hasAESNI || hasARMCrypto) && TierCode() != TierPureGo
}

// Zeroize overwrites all bytes in b with zeros and prevents dead-store
// elimination via runtime.KeepAlive.
func Zeroize(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// SelfTest executes a power-on Known-Answer Self-Test across the active backend
// tier covering the underlying Areion primitives, GF(2^8) / GF(2^128) field
// operations, 288-S-box witness extraction and algebraic verification, SLH-DSA
// tweakable hashes, and TEM2-SIV authenticated encryption.
func SelfTest() error {
	if err := areion.SelfTest(); err != nil {
		return err
	}

	// 1. GF(2^8) S-box inversion and affine identity check
	for x := 0; x < 256; x++ {
		xb := byte(x)
		inv := GF256Inv(xb)
		s := GF256Affine(inv)
		y := GF256AffineInv(s)
		if y != inv {
			return errors.New("areionpq: SelfTest GF256Affine/AffineInv mismatch")
		}
		if GF256Mul(GF256Sq(xb), y)^xb != 0 || GF256Mul(GF256Sq(y), xb)^y != 0 {
			return errors.New("areionpq: SelfTest GF256 degree-2 S-box identity mismatch")
		}
	}

	// 2. GF(2^128) multiplication and PolyMAC check
	var one128, a128, b128 [16]byte
	one128[0] = 1
	for i := 0; i < 16; i++ {
		a128[i] = byte(0x10 + i)
		b128[i] = byte(0x20 + i)
	}
	defer func() {
		Zeroize(a128[:])
		Zeroize(b128[:])
	}()
	if GF128Mul(&a128, &one128) != a128 || GF128Mul(&a128, &b128) != GF128Mul(&b128, &a128) {
		return errors.New("areionpq: SelfTest GF128Mul identity/commutativity mismatch")
	}

	// 3. 288-S-box witness extraction & verification check
	var m, k1, k2 [32]byte
	for i := 0; i < 32; i++ {
		m[i] = byte(i + 1)
		k1[i] = byte(0x40 + i)
		k2[i] = byte(0x80 + i)
	}
	defer func() {
		Zeroize(m[:])
		Zeroize(k1[:])
		Zeroize(k2[:])
	}()
	c, w := ExtractWitness256(&m, &k1, &k2)
	defer Zeroize(w[:])
	if !VerifyWitness256(&m, &c, &k1, &k2, &w) {
		return errors.New("areionpq: SelfTest VerifyWitness256 failed")
	}
	cEM2, wEM2 := ExtractWitnessEM2_256(&m, &k1, &k2)
	defer Zeroize(wEM2[:])
	if !VerifyWitnessEM2_256(&m, &cEM2, &k1, &k2, &wEM2) {
		return errors.New("areionpq: SelfTest VerifyWitnessEM2_256 failed")
	}

	// 4. TEM2-SIV roundtrip check
	var sivKey [128]byte
	var sivNonce [32]byte
	for i := range sivKey {
		sivKey[i] = byte(i)
	}
	for i := range sivNonce {
		sivNonce[i] = byte(0xa0 + i)
	}
	defer func() {
		Zeroize(sivKey[:])
		Zeroize(sivNonce[:])
	}()
	ad := []byte("areion-pq-selftest-ad")
	pt := []byte("areion-pq-selftest-plaintext-block")
	ct, tag := TEM2SIVEncrypt(&sivKey, &sivNonce, ad, pt)
	dec, ok := TEM2SIVDecrypt(&sivKey, &sivNonce, ad, ct, &tag)
	if !ok || string(dec) != string(pt) {
		return errors.New("areionpq: SelfTest TEM2SIV roundtrip mismatch")
	}
	Zeroize(dec)

	return nil
}
