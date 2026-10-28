// Package areionpq implements post-quantum cryptographic signature schemes,
// authenticated key encapsulation / hybrid public-key encryption (HPKE), and
// wide-block misuse-resistant authenticated encryption built on the Areion-256
// and Areion-512 cryptographic permutations.
//
// All primitives execute in constant time with respect to secret inputs and
// scrub temporary stack buffers, SIMD vector registers, and scratch
// general-purpose registers before returning.
//
// # Cryptographic Constructions
//
// The package is organized into three post-quantum tracks:
//
//	Track 1 — FAEST-Areion (VOLE-in-the-Head Zero-Knowledge Signatures):
//	  - FAEST-Areion-128s, FAEST-Areion-128f (NIST Category 1, 48 B PK, 6,448 / 7,456 B Sig)
//	  - FAEST-Areion-256s, FAEST-Areion-256f (NIST Category 5, 64 B PK, 18,208 / 20,512 B Sig)
//	  - FAEST-Areion-EM2-256s, FAEST-Areion-EM2-256f (2-Round Even-Mansour with Orthomorphism)
//	  Exploits the 2-branch Feistel structure of 10-round Areion-256 so that
//	  Round 9 requires zero committed witness bytes (288 committed S-box bytes
//	  out of 320 total S-boxes), verified via degree-2 QuickSilver polynomial
//	  authentication over GF(2^8) and GF(2^128).
//
//	Track 2 — SLH-DSA-Areion (NIST FIPS 205 Stateless Hash-Based Signatures):
//	  - SLH-DSA-Areion-128f, SLH-DSA-Areion-128s (32 B PK, 17,088 / 7,856 B Sig)
//	  - SLH-DSA-Areion-256f, SLH-DSA-Areion-256s (64 B PK, 49,856 / 29,792 B Sig)
//	  - SLH-DSA-Areion-TEM-256f (Tweakable Even-Mansour middle-tweak profile)
//	  Instantiates the FIPS 205 tweakable hash family (F, H, T_l, PRF, PRF_msg,
//	  H_msg) with single-call DM256, DM512, SoEM256, SoEM256x4, SoEM512, and
//	  TEMEncrypt256 after a one-time seed expansion (SLHExpandSeed128/256).
//
//	Track 3 — Areion-HPKE & Areion-TEM2-SIV Wide-Block AEAD:
//	  - KDFExpand: DM512 sponge absorption + 4-way SoEM512x4 counter keystream
//	  - TEM2SIVEncrypt / TEM2SIVDecrypt: 256-bit misuse-resistant SIV tag via
//	    SoEM512x4 followed by wide-block TEM2Encrypt512x4 encryption
//	  - HPKEDeriveKeys, HPKESealDet / HPKEOpenDet, HPKESealMLKEM768 / HPKEOpenMLKEM768
//
// # Hardware Acceleration and Runtime Dispatch
//
// At package initialization, the highest supported instruction-set tier is
// selected automatically:
//
//   - x86-64 (amd64): [TierAVX512] ("avx512"), [TierVAESAVX2] ("vaesavx2"),
//     [TierVEX] ("vex"), [TierAESNI] ("aesni"), or [TierPureGo] ("purego").
//   - ARM64 (arm64): [TierARM64] ("arm64") or [TierPureGo] ("purego").
//   - Other architectures: constant-time 64-bit bitsliced [TierPureGo] ("purego").
//
// Use [Tier], [TierCode], [AvailableTiers], [SetTier], [SetTierCode], or the
// AREION_PQ_FORCE_TIER environment variable to inspect or override the active
// tier at runtime.
package areionpq
