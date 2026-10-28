## Public API Reference (`github.com/everanium/areion-pq`)

Complete reference for all exported constants, types, methods, and functions in package `areionpq` ([`constants.go`](constants.go), [`cpu.go`](cpu.go), [`areion_pq.go`](areion_pq.go)).
For architectural details, security proofs, algebraic analysis, and benchmarks, see [`README.md`](README.md) and [`analysis/README.md`](analysis/README.md).
Built on **[`everanium/areion`](https://github.com/everanium/areion)**; companion C99 / C11 reference library: **[`everanium/areion-pq-c`](https://github.com/everanium/areion-pq-c)** ([`API.md`](https://github.com/everanium/areion-pq-c/blob/main/API.md)).

---

## Table of Contents

1. [Types and Constants](#1-types-and-constants)
2. [Runtime Dispatch, Self-Test, and Memory Zeroization](#2-runtime-dispatch-self-test-and-memory-zeroization)
3. [Finite-Field Arithmetic, Orthomorphisms, and 288-S-Box Witness Primitives](#3-finite-field-arithmetic-orthomorphisms-and-288-s-box-witness-primitives)
4. [Track 1: FAEST-Areion VOLE-in-the-Head Zero-Knowledge Signatures](#4-track-1-faest-areion-vole-in-the-head-zero-knowledge-signatures)
5. [Track 2: SLH-DSA-Areion Stateless Hash-Based Signatures (NIST FIPS 205)](#5-track-2-slh-dsa-areion-stateless-hash-based-signatures-nist-fips-205)
6. [Track 3: Areion-HPKE Key Encapsulation, KDFExpand, and Areion-TEM2-SIV Wide-Block AEAD](#6-track-3-areion-hpke-key-encapsulation-kdfexpand-and-areion-tem2-siv-wide-block-aead)
7. [Standard Library `crypto.Signer` Key Types and Methods](#7-standard-library-cryptosigner-key-types-and-methods)
8. [Zeroization & Stack Hygiene Guarantees](#8-zeroization--stack-hygiene-guarantees)
9. [Usage Examples](#9-usage-examples)

---

### 1. Types and Constants

#### 1.1 Execution Tier Type and Constants (`cpu.go`)

`type TierID int` identifies a hardware or software execution tier returned by `TierCode()` and accepted by `SetTierCode(id TierID)`.

| Constant | Type | Value | Tier Name (`Tier()`) | Required ISA Extensions |
| :--- | :---: | :---: | :---: | :--- |
| `TierAuto` | `TierID` | `0` | (auto-select) | Selects the highest supported hardware tier at initialization |
| `TierPureGo` | `TierID` | `1` | `"purego"` | Portable constant-time 64-bit bitsliced software fallback (all architectures) |
| `TierAESNI` | `TierID` | `2` | `"aesni"` | `x86-64` legacy 2-operand SSE `AES-NI` + `PCLMULQDQ` (128-bit XMM) |
| `TierVEX` | `TierID` | `3` | `"vex"` | `x86-64` `AVX + AES-NI + PCLMULQDQ` 3-operand VEX-encoded XMM |
| `TierVAESAVX2` | `TierID` | `4` | `"vaesavx2"` | `x86-64` `AVX2 + VAES + VPCLMULQDQ` (256-bit YMM Vector AES) |
| `TierAVX512` | `TierID` | `5` | `"avx512"` | `x86-64` `AVX-512F + AVX-512DQ + AVX-512BW + AVX-512VL + VAES + VPCLMULQDQ` (512-bit ZMM) |
| `TierARM64` | `TierID` | `6` | `"arm64"` | `ARM64` `NEON + ARMv8 Cryptographic Extension` (`AESE` / `AESMC` / `PMULL` / `PMULL2`) |
| `TierARMCrypto` | `TierID` | `6` | `"arm64"` | Alias for `TierARM64` |

#### 1.2 Version, Block, State, and Witness Size Constants (`constants.go`)

| Constant | Value | Description |
| :--- | :---: | :--- |
| `Version` | `"0.1.0"` | Semantic version string of `areion-pq` |
| `VersionMajor` | `0` | Major version number |
| `VersionMinor` | `1` | Minor version number |
| `VersionPatch` | `0` | Patch version number |
| `BlockSize` | `16` | 128-bit AES / `GF(2^128)` block size in bytes |
| `State256Size` | `32` | 256-bit `Areion-256` permutation state size in bytes |
| `State512Size` | `64` | 512-bit `Areion-512` permutation state size in bytes |
| `Witness256Size` | `288` | Committed S-box witness size in bytes for 10-round `Areion-256` (`9 × 32 B`; Round 9 has 32 free S-boxes) |
| `WitnessEM2_256Size` | `576` | Committed S-box witness size in bytes for 20-round `Areion-EM2-256` (`2 × 288 B` across `P1` and `P2`) |

#### 1.3 Track 1 (`FAEST-Areion`) Key and Signature Size Constants (`constants.go`)

| Constant | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `FAEST128SeedSize` | `32` | Keygen seed size for `FAEST-Areion-128{s,f}` (`K(16) \|\| PK.seed(16)`) |
| `FAEST128PublicKeySize` | `48` | Public key size for `FAEST-Areion-128{s,f}` (`PK.seed(16) \|\| C(32)`) |
| `FAEST128SecretKeySize` | `64` | Secret key size for `FAEST-Areion-128{s,f}` (`K(16) \|\| PK.seed(16) \|\| C(32)`) |
| `FAEST128sSigSize` | `6448` | Signature size for `FAEST-Areion-128s` (`tau = 13`, small signature profile) |
| `FAEST128fSigSize` | `7456` | Signature size for `FAEST-Areion-128f` (`tau = 16`, fast signing profile) |
| `FAEST256SeedSize` | `64` | Keygen seed size for `FAEST-Areion-256{s,f}` (`K1(32) \|\| PK.seed(32)`) |
| `FAEST256PublicKeySize` | `64` | Public key size for `FAEST-Areion-256{s,f}` (`PK.seed(32) \|\| C(32)`) |
| `FAEST256SecretKeySize` | `96` | Secret key size for `FAEST-Areion-256{s,f}` (`K1(32) \|\| PK.seed(32) \|\| C(32)`) |
| `FAEST256sSigSize` | `18208` | Signature size for `FAEST-Areion-256s` (`tau = 26`, small signature profile) |
| `FAEST256fSigSize` | `20512` | Signature size for `FAEST-Areion-256f` (`tau = 32`, fast signing profile) |
| `FAESTEM2256SeedSize` | `64` | Keygen seed size for `FAEST-Areion-EM2-256{s,f}` (`K1(32) \|\| PK.seed(32)`) |
| `FAESTEM2256PublicKeySize` | `64` | Public key size for `FAEST-Areion-EM2-256{s,f}` (`PK.seed(32) \|\| C(32)`) |
| `FAESTEM2256SecretKeySize` | `96` | Secret key size for `FAEST-Areion-EM2-256{s,f}` (`K1(32) \|\| PK.seed(32) \|\| C(32)`) |
| `FAESTEM2256sSigSize` | `25696` | Signature size for `FAEST-Areion-EM2-256s` (`tau = 26`, 20-round `2-EM` small profile) |
| `FAESTEM2256fSigSize` | `30368` | Signature size for `FAEST-Areion-EM2-256f` (`tau = 32`, 20-round `2-EM` fast profile) |

#### 1.4 Track 2 (`SLH-DSA-Areion`) Key and Signature Size Constants (`constants.go`)

| Constant | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `SLHDSA128SeedSize` | `48` | Keygen seed size for `SLH-DSA-Areion-128{f,s}` (`SK.seed(16) \|\| SK.prf(16) \|\| PK.seed(16)`) |
| `SLHDSA128PublicKeySize` | `32` | Public key size for `SLH-DSA-Areion-128{f,s}` (`PK.seed(16) \|\| PK.root(16)`) |
| `SLHDSA128SecretKeySize` | `64` | Secret key size for `SLH-DSA-Areion-128{f,s}` (`SK.seed(16) \|\| SK.prf(16) \|\| PK.seed(16) \|\| PK.root(16)`) |
| `SLHDSA128fSigSize` | `17088` | Signature size for `SLH-DSA-Areion-128f` (FIPS 205 Category 1 fast profile) |
| `SLHDSA128sSigSize` | `7856` | Signature size for `SLH-DSA-Areion-128s` (FIPS 205 Category 1 small profile) |
| `SLHDSA256SeedSize` | `96` | Keygen seed size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`SK.seed(32) \|\| SK.prf(32) \|\| PK.seed(32)`) |
| `SLHDSA256PublicKeySize` | `64` | Public key size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`PK.seed(32) \|\| PK.root(32)`) |
| `SLHDSA256SecretKeySize` | `128` | Secret key size for `SLH-DSA-Areion-{,TEM-}256{f,s}` (`SK.seed(32) \|\| SK.prf(32) \|\| PK.seed(32) \|\| PK.root(32)`) |
| `SLHDSA256fSigSize` | `49856` | Signature size for `SLH-DSA-Areion-256f` and `SLH-DSA-Areion-TEM-256f` (FIPS 205 Category 5 fast profile) |
| `SLHDSA256sSigSize` | `29792` | Signature size for `SLH-DSA-Areion-256s` (FIPS 205 Category 5 small profile) |

#### 1.5 Track 3 (`Areion-HPKE` & `Areion-TEM2-SIV`) Size Constants (`constants.go`)

| Constant | Value (Bytes) | Description |
| :--- | :---: | :--- |
| `TEM2SIVKeySize` | `128` | 1024-bit `Areion-TEM2-SIV` AEAD key size (`K1(64) \|\| K2(64)`) |
| `TEM2SIVNonceSize` | `32` | 256-bit `Areion-TEM2-SIV` nonce size |
| `TEM2SIVTagSize` | `32` | 256-bit `Areion-TEM2-SIV` synthetic IV authentication tag size |
| `HPKESharedSize` | `32` | 256-bit KEM shared secret size (`ML-KEM-768`) |
| `HPKEKeySeedSize` | `64` | 512-bit `ML-KEM-768` deterministic key generation seed size (`d(32) \|\| z(32)`) |

---

### 2. Runtime Dispatch, Self-Test, and Memory Zeroization

Runtime CPU tier introspection/override (synchronized with the underlying `github.com/everanium/areion` tier), FIPS 140-3 Known-Answer Self-Test (CAST), and DSE-resistant buffer scrubbing ([`cpu.go`](cpu.go)).

| Function Signature | Return Type | Description |
| :--- | :---: | :--- |
| `Tier() string` | `string` | Active dispatch tier name: `"avx512"`, `"vaesavx2"`, `"vex"`, `"aesni"`, `"arm64"`, or `"purego"` |
| `TierCode() TierID` | `TierID` | Active dispatch tier identifier (`TierPureGo`..`TierARM64`) |
| `AvailableTiers() []string` | `[]string` | Ordered slice of execution tier names supported on the current CPU (always begins with `"purego"`) |
| `SetTier(name string) error` | `error` | Overrides the active tier (`"auto"`, `"avx512"`, `"vaesavx2"`, `"vex"`, `"aesni"`, `"arm64"`, `"purego"`, plus aliases `"neon"`/`"sve"`/`"sve2"` and `"purec"`/`"scalar"`/`"gpr"`) and synchronizes `areion.SetTier`; also configurable at startup via `AREION_PQ_FORCE_TIER` |
| `SetTierCode(id TierID) error` | `error` | Overrides the active tier by `TierID` (`TierAuto`..`TierARM64`) |
| `UseHardwareAcceleration() bool` | `bool` | Reports whether hardware AES / carry-less multiplication acceleration is available and currently enabled (`TierCode() != TierPureGo`) |
| `SelfTest() error` | `error` | Executes a power-on Known-Answer Self-Test across `areion.SelfTest()`, `GF(2^8)` degree-2 S-box identities, `GF(2^128)` multiplication, 288/576-S-box witness extraction & verification, and `TEM2-SIV` roundtrip |
| `Zeroize(b []byte)` | — | Overwrites `b` with zeros and prevents dead-store elimination via `clear(b); runtime.KeepAlive(b)` |

---

### 3. Finite-Field Arithmetic, Orthomorphisms, and 288-S-Box Witness Primitives

Constant-time arithmetic in `GF(2^8)`, `GF(2^128)`, and `GF(2^256)`, `GF(2)`-linear key orthomorphisms, and 288-byte / 576-byte S-box witness extraction and degree-2 algebraic verification ([`areion_pq.go`](areion_pq.go)).

#### 3.1 `GF(2^8)`, `GF(2^128)`, `GF(2^256)`, and Key Orthomorphisms

| Function Signature | Domain / Width | Description |
| :--- | :---: | :--- |
| `GF256Mul(a, b byte) byte` | `GF(2^8)` (1 B) | Constant-time product in `GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (modulus `0x11B`) |
| `GF256Sq(a byte) byte` | `GF(2^8)` (1 B) | Constant-time squaring `a^2` in `GF(2^8)` modulo `0x11B` |
| `GF256Inv(a byte) byte` | `GF(2^8)` (1 B) | Constant-time inversion `a^254` in `GF(2^8)` modulo `0x11B` (with `0 -> 0`) |
| `GF256Affine(a byte) byte` | `GF(2)^8` (1 B) | Forward FIPS 197 AES affine transformation over `GF(2)` (including `⊕ 0x63`); `GF256Affine(GF256Inv(x)) == S(x)` |
| `GF256AffineInv(s byte) byte` | `GF(2)^8` (1 B) | Inverse AES affine map (`u = s ⊕ 0x63`, then inverse `GF(2)` matrix); maps `s = S(x)` to `y = GF256Inv(x)` |
| `GF128Mul(a, b *[16]byte) [16]byte` | `GF(2^128)` (16 B) | Hardware-dispatched (`VPCLMULQDQ` / `PCLMULQDQ` / `PMULL`) product in `GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)` (`0x87`) |
| `GF128PolyMAC(a, b [][16]byte, chi *[16]byte) [16]byte` | `GF(2^128)` (16 B) | Hardware-dispatched Horner polynomial accumulation `acc = GF128Mul(acc, chi) ⊕ GF128Mul(a[i], b[i])` over `i = 0..min(len(a),len(b))-1` |
| `GF256FieldMul(a, b *[32]byte) [32]byte` | `GF(2^256)` (32 B) | Karatsuba multiplication in the quadratic extension `GF(2^128)[Y] / (Y^2 + Y + alpha)` where `alpha = 0x87` |
| `MulOrtho256(t, k *[32]byte) [32]byte` | 32 B → 32 B | 2-lane `GF(2^128)` public-tweak orthomorphism `(GF128Mul(T[0:16], K[0:16]), GF128Mul(T[16:32], K[16:32]))` |
| `OrthoSigma256(k *[32]byte) [32]byte` | 32 B → 32 B | Fixed-key Feistel orthomorphism `sigma(K_L \|\| K_R) = K_R \|\| (K_L ⊕ K_R)` (`sigma^2 ⊕ sigma ⊕ id = 0`) |

#### 3.2 288-S-Box and 576-S-Box Witness Extraction and Algebraic Verification

By the Free-Round Witness Theorem ([`analysis/README.md`](analysis/README.md#a-free-round-witness-theorem-areion-256-areion-em2-256-and-areion-512)), recording the 288 state bytes of rounds `0..8` of 10-round `Areion-256` fixes all 320 S-box input/output pairs across rounds `0..9` with zero committed witness bytes in Round 9 (`32` free S-boxes). Each S-box pair `(X, S)` is verified via the coupled degree-2 `GF(2^8)` bilinear identities `Sq(X) * Y ⊕ X == 0` and `Sq(Y) * X ⊕ Y == 0` where `Y = GF256AffineInv(S)`.

| Function Signature | Witness Size | S-Boxes (Free) | Description |
| :--- | :---: | :---: | :--- |
| `ExtractWitness256(m, k1, k2 *[32]byte) (c [32]byte, w [288]byte)` | 288 B | 320 (32 free) | Computes `C = P1_256(M ⊕ K1) ⊕ K2` and extracts the 288-byte committed witness for rounds `0..8` of `P1` |
| `ExtractWitness256P2(m, k1, k2 *[32]byte) (c [32]byte, w [288]byte)` | 288 B | 320 (32 free) | Computes `C = P2_256(M ⊕ K1) ⊕ K2` and extracts the 288-byte committed witness for rounds `0..8` of `P2` |
| `VerifyWitness256(m, c, k1, k2 *[32]byte, w *[288]byte) bool` | 288 B | 320 (32 free) | Constant-time algebraic verification of all 320 S-box degree-2 `GF(2^8)` equations of `P1_256` |
| `VerifyWitness256P2(m, c, k1, k2 *[32]byte, w *[288]byte) bool` | 288 B | 320 (32 free) | Constant-time algebraic verification of all 320 S-box degree-2 `GF(2^8)` equations of `P2_256` |
| `ExtractWitnessEM2_256(m, k1, k2 *[32]byte) (c [32]byte, w [576]byte)` | 576 B | 640 (64 free) | Computes `C = P2_256(P1_256(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2` and extracts the 576-byte witness (`288 B` `P1` + `288 B` `P2`) |
| `VerifyWitnessEM2_256(m, c, k1, k2 *[32]byte, w *[576]byte) bool` | 576 B | 640 (64 free) | Constant-time algebraic verification of all 640 S-box degree-2 `GF(2^8)` equations across `P1_256` and `P2_256` |

---

### 4. Track 1: FAEST-Areion VOLE-in-the-Head Zero-Knowledge Signatures

Post-quantum zero-knowledge signature schemes built on the `Areion-256` one-way function `C = P1_256(M ⊕ K1) ⊕ MulOrtho256(T, K1)` (`FAEST-Areion-128{s,f}` and `FAEST-Areion-256{s,f}`) and the 20-round 2-round Even-Mansour one-way function `C = P2_256(P1_256(M ⊕ K1) ⊕ sigma(K1)) ⊕ K1 ⊕ sigma(K1)` (`FAEST-Areion-EM2-256{s,f}`). Pass `optRand = nil` for deterministic signing or a random byte array to hedge against fault/side-channel attacks.

| Function Signature | Seed / PK / SK | Signature | Security Category |
| :--- | :---: | :---: | :--- |
| `FAESTKeygen128s(seed *[32]byte) (pk [48]byte, sk [64]byte)` | 32 / 48 / 64 B | — | NIST Category 1 (`lambda = 128`, `tau = 13`) |
| `FAESTSign128s(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [6448]byte)` | SK: 64 B | 6,448 B | NIST Category 1 small signature profile |
| `FAESTVerify128s(pk *[48]byte, msg []byte, sig *[6448]byte) bool` | PK: 48 B | 6,448 B | Constant-time `QuickSilver` + GGM verification |
| `FAESTKeygen128f(seed *[32]byte) (pk [48]byte, sk [64]byte)` | 32 / 48 / 64 B | — | NIST Category 1 (`lambda = 128`, `tau = 16`) |
| `FAESTSign128f(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [7456]byte)` | SK: 64 B | 7,456 B | NIST Category 1 fast signing profile |
| `FAESTVerify128f(pk *[48]byte, msg []byte, sig *[7456]byte) bool` | PK: 48 B | 7,456 B | Constant-time `QuickSilver` + GGM verification |
| `FAESTKeygen256s(seed *[64]byte) (pk [64]byte, sk [96]byte)` | 64 / 64 / 96 B | — | NIST Category 5 (`lambda = 256`, `tau = 26`) |
| `FAESTSign256s(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [18208]byte)` | SK: 96 B | 18,208 B | NIST Category 5 small signature profile |
| `FAESTVerify256s(pk *[64]byte, msg []byte, sig *[18208]byte) bool` | PK: 64 B | 18,208 B | Constant-time `QuickSilver` + GGM verification |
| `FAESTKeygen256f(seed *[64]byte) (pk [64]byte, sk [96]byte)` | 64 / 64 / 96 B | — | NIST Category 5 (`lambda = 256`, `tau = 32`) |
| `FAESTSign256f(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [20512]byte)` | SK: 96 B | 20,512 B | NIST Category 5 fast signing profile |
| `FAESTVerify256f(pk *[64]byte, msg []byte, sig *[20512]byte) bool` | PK: 64 B | 20,512 B | Constant-time `QuickSilver` + GGM verification |
| `FAESTEM2Keygen256s(seed *[64]byte) (pk [64]byte, sk [96]byte)` | 64 / 64 / 96 B | — | NIST Category 5 20-round `2-EM` (`tau = 26`) |
| `FAESTEM2Sign256s(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [25696]byte)` | SK: 96 B | 25,696 B | NIST Category 5 `2-EM` small signature profile |
| `FAESTEM2Verify256s(pk *[64]byte, msg []byte, sig *[25696]byte) bool` | PK: 64 B | 25,696 B | Constant-time 640-S-box `QuickSilver` verification |
| `FAESTEM2Keygen256f(seed *[64]byte) (pk [64]byte, sk [96]byte)` | 64 / 64 / 96 B | — | NIST Category 5 20-round `2-EM` (`tau = 32`) |
| `FAESTEM2Sign256f(sk *[96]byte, msg []byte, optRand *[32]byte) (sig [30368]byte)` | SK: 96 B | 30,368 B | NIST Category 5 `2-EM` fast signing profile |
| `FAESTEM2Verify256f(pk *[64]byte, msg []byte, sig *[30368]byte) bool` | PK: 64 B | 30,368 B | Constant-time 640-S-box `QuickSilver` verification |

---

### 5. Track 2: SLH-DSA-Areion Stateless Hash-Based Signatures (NIST FIPS 205)

Stateless hash-based signatures conforming to the `NIST FIPS 205` hypertree + `FORS` + `WOTS+` architecture, instantiated with domain-separated `Areion-512` Davies-Meyer (`DM512`), `SoEM256` / `SoEM256x4` PRFs, and middle-tweak `TEMEncrypt256`.

#### 5.1 Seed Expansion, Address Compression, and Tweakable Hash Primitives

| Function Signature | Output | Description |
| :--- | :---: | :--- |
| `SLHExpandSeed128(pkSeed, skSeed *[16]byte) (kPub, kSK [64]byte)` | 2 × 64 B | Expands 16-byte `PK.seed` and optional `SK.seed` (`nil` during verify) into 64-byte `K_pub` and `K_sk` |
| `SLHExpandSeed256(pkSeed, skSeed *[32]byte) (kPub, kSK [64]byte)` | 2 × 64 B | Expands 32-byte `PK.seed` and optional `SK.seed` (`nil` during verify) into 64-byte `K_pub` and `K_sk` |
| `SLHCompactADRS(adrs *[32]byte) [16]byte` | 16 B | Extracts all 16 active bytes (`128` bits, `GF(2)` rank `128 / 128`) of a 32-byte `FIPS 205` `ADRS` structure |
| `SLHPRF128(kSK *[64]byte, adrs *[32]byte) [16]byte` | 16 B | Secret-key address PRF `SoEM256(K_sk, ADRS)[0:16]` for `n = 16` |
| `SLHPRF256(kSK *[64]byte, adrs *[32]byte) [32]byte` | 32 B | Secret-key address PRF `SoEM256(K_sk, ADRS)` for `n = 32` |
| `SLHPRF256x4(kSK *[64]byte, adrs *[4][32]byte) [4][32]byte` | 4 × 32 B | 4-way parallel `SoEM256x4` evaluation of `SLHPRF256` across 4 distinct addresses |
| `SLHF128(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1 *[16]byte) [16]byte` | 16 B | Category 1 tweakable chain hash `DM512((PK.seed \|\| ADRS \|\| M_1) ⊕ K_pub)[0:16]` (`384`-bit clamped tweak capacity) |
| `SLHF256(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte` | 32 B | Profile I (`DM512-Clamped`) tweakable chain hash `DM512((ADRS ⊕ K_pub1) \|\| (M_1 ⊕ K_pub2))` (`256`-bit clamped tweak capacity) |
| `SLHFTEM256(kPub *[64]byte, adrs *[32]byte, m1 *[32]byte) [32]byte` | 32 B | Profile II (`TEM-MiddleTweak`) tweakable chain hash `TEMEncrypt256(K_pub, M_1, ADRS) ⊕ M_1` |
| `SLHH128(pkSeed *[16]byte, kPub *[64]byte, adrs *[32]byte, m1, m2 *[16]byte) [16]byte` | 16 B | Category 1 2-to-1 Merkle tree hash `DM512((PK.seed \|\| ADRS_compact \|\| M_1 \|\| M_2) ⊕ K_pub)[0:16]` |
| `SLHH256(kPub *[64]byte, adrs *[32]byte, m1, m2 *[32]byte) [32]byte` | 32 B | Category 5 2-step cascaded `DM512` 2-to-1 Merkle tree hash `H(K_pub, ADRS, M_1 \|\| M_2)` |
| `SLHTl128(kPub *[64]byte, adrs *[32]byte, blocks [][16]byte) [16]byte` | 16 B | Category 1 multi-block tweakable hash `T_l(K_pub, ADRS, blocks)` compressing `WOTS+` / `FORS` public keys |
| `SLHTl256(kPub *[64]byte, adrs *[32]byte, blocks [][32]byte) [32]byte` | 32 B | Category 5 multi-block tweakable hash `T_l(K_pub, ADRS, blocks)` compressing `WOTS+` / `FORS` public keys |

#### 5.2 Key Generation, Signing, and Verification Entry Points

| Function Signature | Seed / PK / SK | Signature | Profile & Security Category |
| :--- | :---: | :---: | :--- |
| `SLHDSAKeygen128f(seed *[48]byte) (pk [32]byte, sk [64]byte)` | 48 / 32 / 64 B | — | FIPS 205 Cat 1 fast (`n=16, h=66, d=22, a=6, k=33`) |
| `SLHDSASign128f(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [17088]byte)` | SK: 64 B | 17,088 B | FIPS 205 Cat 1 fast signing (`optRand = nil` -> deterministic) |
| `SLHDSAVerify128f(pk *[32]byte, msg []byte, sig *[17088]byte) bool` | PK: 32 B | 17,088 B | Constant-time root comparison |
| `SLHDSAKeygen128s(seed *[48]byte) (pk [32]byte, sk [64]byte)` | 48 / 32 / 64 B | — | FIPS 205 Cat 1 small (`n=16, h=63, d=7, a=12, k=14`) |
| `SLHDSASign128s(sk *[64]byte, msg []byte, optRand *[16]byte) (sig [7856]byte)` | SK: 64 B | 7,856 B | FIPS 205 Cat 1 small signing (`optRand = nil` -> deterministic) |
| `SLHDSAVerify128s(pk *[32]byte, msg []byte, sig *[7856]byte) bool` | PK: 32 B | 7,856 B | Constant-time root comparison |
| `SLHDSAKeygen256f(seed *[96]byte) (pk [64]byte, sk [128]byte)` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 fast (`n=32, h=68, d=17, a=9, k=35`, Profile I `DM512-Clamped`) |
| `SLHDSASign256f(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [49856]byte)` | SK: 128 B | 49,856 B | FIPS 205 Cat 5 fast signing (4-way `WOTS+` batched) |
| `SLHDSAVerify256f(pk *[64]byte, msg []byte, sig *[49856]byte) bool` | PK: 64 B | 49,856 B | Constant-time root comparison |
| `SLHDSAKeygen256s(seed *[96]byte) (pk [64]byte, sk [128]byte)` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 small (`n=32, h=64, d=8, a=14, k=22`, Profile I `DM512-Clamped`) |
| `SLHDSASign256s(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [29792]byte)` | SK: 128 B | 29,792 B | FIPS 205 Cat 5 small signing (4-way `WOTS+` batched) |
| `SLHDSAVerify256s(pk *[64]byte, msg []byte, sig *[29792]byte) bool` | PK: 64 B | 29,792 B | Constant-time root comparison |
| `SLHDSATEMKeygen256f(seed *[96]byte) (pk [64]byte, sk [128]byte)` | 96 / 64 / 128 B | — | FIPS 205 Cat 5 fast (`n=32, h=68, d=17, a=9, k=35`, Profile II `TEM-MiddleTweak`) |
| `SLHDSATEMSign256f(sk *[128]byte, msg []byte, optRand *[32]byte) (sig [49856]byte)` | SK: 128 B | 49,856 B | FIPS 205 Cat 5 `TEM-MiddleTweak` signing |
| `SLHDSATEMVerify256f(pk *[64]byte, msg []byte, sig *[49856]byte) bool` | PK: 64 B | 49,856 B | Constant-time root comparison |

---

### 6. Track 3: Areion-HPKE Key Encapsulation, KDFExpand, and Areion-TEM2-SIV Wide-Block AEAD

Sponge-based key derivation (`KDFExpand`), 512-bit wide-block misuse-resistant authenticated encryption (`Areion-TEM2-SIV`) with `2^341.3` classical / `2^170.7` quantum BBB security, and post-quantum Hybrid Public-Key Encryption (`ML-KEM-768` + `Areion-TEM2-SIV`).

| Function Signature | Key / Nonce / Tag | Description |
| :--- | :---: | :--- |
| `KDFExpand(secret, context, dst []byte)` | arbitrary → `len(dst)` | Absorbs `secret` and `context` via a domain-separated `DM512` sponge and expands pseudorandom output into `dst` using 4-way `SoEM512x4` |
| `TEM2SIVEncryptInPlace(key *[128]byte, nonce *[32]byte, ad, dst, plaintext []byte) (tag [32]byte)` | 128 / 32 / 32 B | Computes 32-byte SIV tag over `(nonce, ad, plaintext)` via `SoEM512x4` and encrypts `plaintext` into `dst` (`dst` may alias `plaintext`) via `TEM2Encrypt512x4` |
| `TEM2SIVDecryptInPlace(key *[128]byte, nonce *[32]byte, ad, dst, ciphertext []byte, tag *[32]byte) bool` | 128 / 32 / 32 B | Decrypts `ciphertext` into `dst` (`dst` may alias `ciphertext`) and verifies `tag` in constant time; **zeroizes `dst[0:len(ciphertext)]` on failure** |
| `TEM2SIVEncrypt(key *[128]byte, nonce *[32]byte, ad, plaintext []byte) (ciphertext []byte, tag [32]byte)` | 128 / 32 / 32 B | Allocating wrapper around `TEM2SIVEncryptInPlace` |
| `TEM2SIVDecrypt(key *[128]byte, nonce *[32]byte, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, ok bool)` | 128 / 32 / 32 B | Allocating wrapper around `TEM2SIVDecryptInPlace`; returns `(nil, false)` on authentication failure |
| `HPKEDeriveKeys(sharedSecret *[32]byte, info []byte) (demKey [128]byte, baseNonce [32]byte)` | 32 B → 128 + 32 B | Derives a 128-byte `TEM2-SIV` DEM key and 32-byte base nonce from `sharedSecret` and `info` via `KDFExpand` |
| `HPKESealDet(sharedSecret *[32]byte, info []byte, seq uint64, ad, plaintext []byte) (ciphertext []byte, tag [32]byte)` | 32 B + `seq` → CT + 32 B | Deterministically seals `plaintext` under `sharedSecret`, `info`, and sequence number `seq` (`baseNonce ⊕ seq`) |
| `HPKEOpenDet(sharedSecret *[32]byte, info []byte, seq uint64, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, ok bool)` | 32 B + `seq` → PT | Opens and authenticates a ciphertext produced by `HPKESealDet` |
| `HPKESealMLKEM768(encapKeyBytes, info, ad, plaintext []byte) (kemCiphertext, ciphertext []byte, tag [32]byte, err error)` | 1,184 B EK → 1,088 B KEM CT | Encapsulates an ephemeral shared secret to an `ML-KEM-768` encapsulation key (`crypto/mlkem`) and seals `plaintext` with `Areion-TEM2-SIV` |
| `HPKEOpenMLKEM768(decapKey *mlkem.DecapsulationKey768, kemCiphertext, info, ad, ciphertext []byte, tag *[32]byte) (plaintext []byte, err error)` | `*mlkem.DecapsulationKey768` | Decapsulates `kemCiphertext` using `decapKey` and opens `ciphertext` with `Areion-TEM2-SIV` |

---

### 7. Standard Library `crypto.Signer` Key Types and Methods

Wrapper structs implementing the standard library `crypto.Signer` and `crypto.PublicKey` interfaces across all `FAEST-Areion` and `SLH-DSA-Areion` variants.

#### 7.1 `FAESTPublicKey` and `FAESTPrivateKey`

```go
type FAESTPublicKey struct {
	Variant string // "128s", "128f", "256s", "256f", "em2-256s", or "em2-256f"
	Bytes   []byte
}

type FAESTPrivateKey struct {
	Variant string // "128s", "128f", "256s", "256f", "em2-256s", or "em2-256f"
	Bytes   []byte
	Pub     FAESTPublicKey
}
```

| Method Signature | Receiver | Description |
| :--- | :---: | :--- |
| `(pub *FAESTPublicKey) Equal(x crypto.PublicKey) bool` | `*FAESTPublicKey` | Constant-time equality comparison of variant name and key bytes |
| `(pub *FAESTPublicKey) Verify(msg, sig []byte) bool` | `*FAESTPublicKey` | Dispatches signature verification according to `pub.Variant` |
| `(priv *FAESTPrivateKey) Public() crypto.PublicKey` | `*FAESTPrivateKey` | Returns `&priv.Pub` (`crypto.Signer` interface) |
| `(priv *FAESTPrivateKey) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` | `*FAESTPrivateKey` | Reads `optRand` from `randReader` (or `crypto/rand.Reader` if `nil`) and signs `digest` under `priv.Variant` |

#### 7.2 `SLHDSAPublicKey` and `SLHDSAPrivateKey`

```go
type SLHDSAPublicKey struct {
	Variant string // "128f", "128s", "256f", "256s", or "tem-256f"
	Bytes   []byte
}

type SLHDSAPrivateKey struct {
	Variant string // "128f", "128s", "256f", "256s", or "tem-256f"
	Bytes   []byte
	Pub     SLHDSAPublicKey
}
```

| Method Signature | Receiver | Description |
| :--- | :---: | :--- |
| `(pub *SLHDSAPublicKey) Equal(x crypto.PublicKey) bool` | `*SLHDSAPublicKey` | Constant-time equality comparison of variant name and key bytes |
| `(pub *SLHDSAPublicKey) Verify(msg, sig []byte) bool` | `*SLHDSAPublicKey` | Dispatches signature verification according to `pub.Variant` |
| `(priv *SLHDSAPrivateKey) Public() crypto.PublicKey` | `*SLHDSAPrivateKey` | Returns `&priv.Pub` (`crypto.Signer` interface) |
| `(priv *SLHDSAPrivateKey) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)` | `*SLHDSAPrivateKey` | Reads `optRand` from `randReader` (or `crypto/rand.Reader` if `nil`) and signs `digest` under `priv.Variant` |

---

### 8. Zeroization & Stack Hygiene Guarantees

All assembly kernels (`areion_pq_amd64.s`, `areion_pq_arm64.s`) and software routines (`areion_pq.go`, `areion_pq_purego.go`) enforce strict post-call register and memory hygiene:

1. **Zero-Spill Assembly Kernels:** Hardware kernels for `ExtractWitness256` (`AES-NI`, `VEX`, `ARMv8 Crypto`), `GF128Mul` and `GF128PolyMAC` (`PCLMULQDQ`, `VPCLMULQDQ`, `PMULL`/`PMULL2`), and `VOLE` row XOR (`SSE2`, `AVX2`, `AVX-512`, `NEON`) execute with zero stack frame allocations (`NOSPLIT`, 0-byte frame) and zero intermediate stack spills.
2. **Vector & GPR Epilogue Scrubbing:** Every assembly kernel zeroes all touched SIMD vector registers (`PXOR` / `VPXOR` / `VPXORD` + `VZEROUPPER` on `x86-64`; `VEOR` on `arm64`) and volatile scratch general-purpose registers (`XORQ` on `x86-64`; `MOVD ZR` on `arm64`) before `RET`.
3. **Software Stack & Buffer Scrubbing:** Composite Go functions explicitly zeroize temporary buffers via `clear(...)` + `runtime.KeepAlive(...)`, scrub their 1,024-byte software stack window (`wipeSoftwareStack`), and clobber volatile SIMD/GPR registers (`clobberScratchGPRs`).
4. **Unverified Plaintext Zeroization:** `TEM2SIVDecryptInPlace` wipes `dst[0:len(ciphertext)]` to all-zeros whenever tag verification fails, preventing unauthenticated plaintext release.
5. **Canary-Verified Residue Tests:** `TestFusedKernelsLeaveNoSecretInFrame` (`areion_pq_zeroize_test.go`, `areion_pq_zeroize_amd64_test.go`, `areion_pq_zeroize_arm64_test.go`, `areion_pq_zeroize_other_test.go`) validates both positive and negative stack/SIMD/GPR canary controls across every execution tier and target architecture.

---

### 9. Usage Examples

```go
package main

import (
	"crypto/mlkem"
	"fmt"

	areionpq "github.com/everanium/areion-pq"
)

func main() {
	// 0. Run FIPS 140-3 power-on Known-Answer Self-Test
	if err := areionpq.SelfTest(); err != nil {
		panic(err)
	}
	fmt.Printf("Active tier: %s\n", areionpq.Tier())

	// 1. Track 1: FAEST-Areion-128f zero-knowledge signature
	var faestSeed [areionpq.FAEST128SeedSize]byte
	var faestOpt [16]byte
	msg := []byte("post-quantum authenticated message")
	fPK, fSK := areionpq.FAESTKeygen128f(&faestSeed)
	fSig := areionpq.FAESTSign128f(&fSK, msg, &faestOpt)
	fmt.Printf("FAEST-128f verify: %v (sig=%d B)\n", areionpq.FAESTVerify128f(&fPK, msg, &fSig), len(fSig))

	// 2. Track 2: SLH-DSA-Areion-128f stateless hash-based signature
	var slhSeed [areionpq.SLHDSA128SeedSize]byte
	sPK, sSK := areionpq.SLHDSAKeygen128f(&slhSeed)
	sSig := areionpq.SLHDSASign128f(&sSK, msg, &faestOpt)
	fmt.Printf("SLH-DSA-128f verify: %v (sig=%d B)\n", areionpq.SLHDSAVerify128f(&sPK, msg, &sSig), len(sSig))

	// 3. Track 3: ML-KEM-768 + Areion-TEM2-SIV Hybrid Public-Key Encryption (HPKE)
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	info := []byte("areion-pq-hpke-context")
	ad := []byte("associated-header")
	kemCT, ct, tag, err := areionpq.HPKESealMLKEM768(ekBytes, info, ad, msg)
	if err != nil {
		panic(err)
	}
	pt, err := areionpq.HPKEOpenMLKEM768(dk, kemCT, info, ad, ct, &tag)
	if err != nil {
		panic(err)
	}
	fmt.Printf("HPKE roundtrip ok: %v\n", string(pt) == string(msg))

	// 4. Scrub sensitive secret keys and plaintext before returning
	areionpq.Zeroize(fSK[:])
	areionpq.Zeroize(sSK[:])
	areionpq.Zeroize(pt)
}
```
