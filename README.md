## Areion-PQ: Post-Quantum Signatures (`FAEST-Areion`, `SLH-DSA-Areion`) & Wide-Block Hybrid Encryption (`Areion-HPKE`, `Areion-TEM2-SIV`) Go + Assembly Reference Library

Go + Assembly reference implementation of three post-quantum and beyond-birthday-bound cryptographic tracks built on the **Areion-256** and **Areion-512** permutations:
1. **`FAEST-Areion`**: `VOLE-in-the-Head` (`VOLEitH`) and `QuickSilver` degree-2 polynomial zero-knowledge signatures with the **288-S-box Round-9 Free-Witness Theorem** (`FAEST-Areion-128{s,f}`, `FAEST-Areion-256{s,f}`, `FAEST-Areion-EM2-256{s,f}`).
2. **`SLH-DSA-Areion`**: `NIST FIPS 205` stateless hash-based signatures instantiated with clamped-capacity `DM512`, middle-tweak `TEM`, and `SoEM256` PRFs (`SLH-DSA-Areion-128{f,s}`, `SLH-DSA-Areion-256{f,s}`, `SLH-DSA-Areion-TEM-256f`).
3. **`Areion-HPKE` & `Areion-TEM2-SIV`**: Post-quantum Hybrid Public-Key Encryption (`ML-KEM-768` + `AreionKDF`) and 512-bit wide-block misuse-resistant authenticated encryption (`TEM2-SIV`) with `2^341.3` classical / `2^170.7` quantum Beyond-Birthday-Bound (BBB) security.

Built on **[`everanium/areion`](https://github.com/everanium/areion)**. Companion C + Assembly reference library: **[`everanium/areion-pq-c`](https://github.com/everanium/areion-pq-c)**.

[![Go Reference](https://pkg.go.dev/badge/github.com/everanium/areion-pq.svg)](https://pkg.go.dev/github.com/everanium/areion-pq)
[![golangci-lint](https://img.shields.io/badge/golangci--lint-passing-green)](https://golangci-lint.run)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/everanium/areion-pq)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/License-Apache_2.0_OR_MIT-blue.svg)](#license)

---

## Overview

`areion-pq` constructs post-quantum signatures, key derivation, and wide-block authenticated encryption directly over hardware-accelerated `Areion-256` (10-round) and `Areion-512` (15-round) permutations ([Isobe et al., TCHES 2023](https://doi.org/10.46586/tches.v2023.i2.115-154); [ePrint 2023/794](https://eprint.iacr.org/2023/794)):

- **Track 1 — `FAEST-Areion` (`VOLE-in-the-Head` Zero-Knowledge Signatures)**: Exploits the 2-branch Feistel structure of 10-round `Areion-256` so that Round 9 requires **zero committed witness bytes** (`32` free S-boxes out of `320` total S-boxes; `288` witness bytes = `2,304` bits for `Areion-256`, and `576` witness bytes = `4,608` bits for 20-round `Areion-EM2-256`). Every S-box transition `(X, S)` is verified over `GF(2^8)` via the coupled degree-2 bilinear equations `Sq(X) * Y ⊕ X = 0` and `Sq(Y) * X ⊕ Y = 0` (`Y = AffineInv(S)`), which achieve `100%` completeness (`256 / 256` valid pairs, including `(0x00, 0x63)`) and `100%` soundness (`65,280 / 65,280` invalid pairs rejected) under `QuickSilver` `GF(2^128)` polynomial authentication.
- **Track 2 — `SLH-DSA-Areion` (`NIST FIPS 205` Stateless Hash-Based Signatures)**: Replaces sequential 64/80-round `SHA-2` and `SHAKE256` compression in `NIST FIPS 205` with single-call `DM512` (`60` hardware AES instructions per 64-byte compression), 4-way batched `SoEM256x4` address PRFs, and middle-tweak `TEMEncrypt256`, after a one-time seed expansion (`SLHExpandSeed128/256`). Clamped-capacity `DM512` (`SLHF256`, `SLHF128`, `SLHH128`) and middle-tweak `TEM` (`SLHFTEM256`) preserve full `256 / 256` tweak capacity rank and eliminate feed-forward tweak cancellation.
- **Track 3 — `Areion-HPKE` & `Areion-TEM2-SIV` Wide-Block AEAD**: Combines `NIST FIPS 203` `ML-KEM-768` (`crypto/mlkem`), a domain-separated `DM512` + `SoEM512x4` sponge key derivation function (`KDFExpand`), and 512-bit wide-block Synthetic IV authenticated encryption (`TEM2SIVEncrypt` / `TEM2SIVDecrypt`) built from `SoEM512x4` tag authentication and 4-way `TEM2Encrypt512x4` / `TEM2Decrypt512x4` wide-block tweakable encryption (`2^341.3` classical / `2^170.7` quantum BBB security).
- **Multi-Tier Hardware Dispatch & Portable Fallback**: Automatic runtime selection across `AVX-512 VAES + VPCLMULQDQ`, `AVX2 + VAES + VPCLMULQDQ`, `AVX + AES-NI + PCLMULQDQ (VEX)`, legacy `AES-NI + PCLMULQDQ`, `ARMv8 Crypto (AESE/AESMC + PMULL/PMULL2)`, and a constant-time 64-bit bitsliced software fallback (`purego`), verified at startup by `SelfTest()`.
- **Constant-Time & Zeroization Hardening**: Zero secret-dependent branches or table lookups, automatic zeroization of unauthenticated `TEM2-SIV` plaintext buffers, and epilogue scrubbing of temporary stack frames, SIMD vector registers (`XMM`/`YMM`/`ZMM`/`V0–V31`), and scratch GPRs before every return.

---

## Public API

**See [`API.md`](API.md) for the complete function-by-function specification, exact Go signatures, type definitions, and parameter sizes.**

| Category | Exported Symbols | Key / Seed | State / Witness / Sig | Summary |
| :--- | :--- | :---: | :---: | :--- |
| **[Constants & Sizes](API.md#1-types-and-constants)** | `Version{,Major,Minor,Patch}`, `BlockSize`, `State{256,512}Size`, `Witness{256,EM2_256}Size`, `FAEST*Size`, `SLHDSA*Size`, `TEM2SIV*Size`, `HPKE*Size` | 32–128 B | 16–49,856 B | Semantic version constants and byte-length constants across all three tracks |
| **[Tier Types & Dispatch](API.md#2-runtime-dispatch-self-test-and-memory-zeroization)** | `TierID`, `TierAuto`, `TierPureGo`, `TierAESNI`, `TierVEX`, `TierVAESAVX2`, `TierAVX512`, `TierARM64`, `TierARMCrypto`, `Tier`, `TierCode`, `AvailableTiers`, `SetTier`, `SetTierCode`, `UseHardwareAcceleration`, `SelfTest`, `Zeroize` | — | — | Runtime ISA tier introspection/override (synchronized with `areion`), FIPS 140-3 CAST `SelfTest`, and DSE-safe `Zeroize` |
| **[Finite Fields & Orthomorphisms](API.md#31-gf28-gf2128-gf2256-and-key-orthomorphisms)** | `GF256{Mul,Sq,Inv,Affine,AffineInv}`, `GF128{Mul,PolyMAC}`, `GF256FieldMul`, `MulOrtho256`, `OrthoSigma256` | 1–32 B | 1–32 B | Constant-time `GF(2^8)`, `GF(2^128)`, and `GF(2^256)` arithmetic, Horner `PolyMAC`, and `GF(2)`-linear key orthomorphisms |
| **[288-S-Box Witness Primitives](API.md#32-288-s-box-and-576-s-box-witness-extraction-and-algebraic-verification)** | `ExtractWitness256{,P2}`, `VerifyWitness256{,P2}`, `ExtractWitnessEM2_256`, `VerifyWitnessEM2_256` | 2 × 32 B | 288 / 576 B | Hardware-accelerated 288-byte (`P1`, `P2`) and 576-byte (`2-EM`) witness extraction and constant-time degree-2 `GF(2^8)` verification |
| **[Track 1: `FAEST-Areion`](API.md#4-track-1-faest-areion-vole-in-the-head-zero-knowledge-signatures)** | `FAEST{Keygen,Sign,Verify}{128s,128f,256s,256f}`, `FAESTEM2{Keygen,Sign,Verify}{256s,256f}` | 32–96 B | 6,448–30,368 B | `VOLE-in-the-Head` + `QuickSilver` zero-knowledge signatures over `Areion-256` (`128s/f`, `256s/f`) and 20-round `Areion-EM2-256` (`EM2-256s/f`) |
| **[Track 2: `SLH-DSA-Areion` Hashes](API.md#51-seed-expansion-address-compression-and-tweakable-hash-primitives)** | `SLHExpandSeed{128,256}`, `SLHCompactADRS`, `SLHPRF{128,256,256x4}`, `SLHF{128,256,TEM256}`, `SLHH{128,256}`, `SLHTl{128,256}` | 16–64 B | 16 / 32 B | `FIPS 205` seed expansion, 128-bit injective `ADRS` compression, `SoEM256` PRFs, and clamped-capacity `DM512` / middle-tweak `TEM` hashes |
| **[Track 2: `SLH-DSA-Areion` Signatures](API.md#52-key-generation-signing-and-verification-entry-points)** | `SLHDSA{Keygen,Sign,Verify}{128f,128s,256f,256s}`, `SLHDSATEM{Keygen,Sign,Verify}256f` | 32–128 B | 7,856–49,856 B | Stateless hash-based keygen, signing, and verification for `128f`, `128s`, `256f`, `256s` (`DM512-Clamped`), and `TEM-256f` (`TEM-MiddleTweak`) |
| **[Track 3: `Areion-HPKE` & `TEM2-SIV`](API.md#6-track-3-areion-hpke-key-encapsulation-kdfexpand-and-areion-tem2-siv-wide-block-aead)** | `KDFExpand`, `TEM2SIV{Encrypt,Decrypt}{,InPlace}`, `HPKEDeriveKeys`, `HPKE{Seal,Open}Det`, `HPKE{Seal,Open}MLKEM768` | 32–128 B | 32 B tag | `DM512` + `SoEM512x4` KDF, 512-bit wide-block `TEM2-SIV` MRAE (`2^341.3` BBB), and `ML-KEM-768` hybrid encryption |
| **[`crypto.Signer` Wrappers](API.md#7-standard-library-cryptosigner-key-types-and-methods)** | `FAESTPublicKey`, `FAESTPrivateKey`, `SLHDSAPublicKey`, `SLHDSAPrivateKey` (`Equal`, `Verify`, `Public`, `Sign`) | 32–128 B | 6,448–49,856 B | Standard library `crypto.Signer` and `crypto.PublicKey` implementations across all `FAEST-Areion` and `SLH-DSA-Areion` parameter sets |

---

## Cryptographic Constructions & Security

### 1. Track 1: `FAEST-Areion` (`VOLE-in-the-Head` Zero-Knowledge Signatures)

`FAEST-Areion` adapts the `FAEST` ([Baum et al., CRYPTO 2023](https://eprint.iacr.org/2023/996)) `VOLE-in-the-Head` (`VOLEitH`) and `QuickSilver` ([Yang et al., CCS 2021](https://eprint.iacr.org/2021/076)) paradigm to the 10-round `Areion-256` permutation.

#### Key Orthomorphisms (`MulOrtho256` and `OrthoSigma256`)
An unconstrained Even-Mansour relation `C = P1(M ⊕ K1) ⊕ K2` with independent `(K1, K2)` has `2^256` valid key pairs per `(M, C)` and admits a trivial 1-query forgery (`K2 = P1(M ⊕ K1) ⊕ C` for arbitrary `K1`). Setting `K2 = K1` eliminates extra key degrees of freedom in 1-round `EM`, but in 2-round `EM2` (`C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2`) causes the outer whitening mask `K1 ⊕ K2` to vanish. `FAEST-Areion` derives `K2 = L(K1)` via a `GF(2)`-linear orthomorphism `L` on `{0,1}^256` (`rank(L) = 256 / 256` and `rank(I ⊕ L) = 256 / 256`):

- **Public-Tweak Orthomorphism (`MulOrtho256`, used in `FAEST-Areion-128{s,f}` and `FAEST-Areion-256{s,f}`)**:
  ```text
  K2 = (GF128Mul(T[0:16], K1[0:16]), GF128Mul(T[16:32], K1[16:32]))
  C  = P1_256(M ⊕ K1) ⊕ K2
  ```
  where `(T, M)` are expanded from `PK.seed` via `SoEM512` and clamped so `T[0] |= 0x02`, `T[16] |= 0x02` (`T_0, T_1` not in `{0, 1}`), guaranteeing that both `K1 -> K2` and `K1 -> K1 ⊕ K2` are bijections over `GF(2)^256` while remaining strictly linear in the secret witness wires `K1`.
- **Fixed-Key Feistel Orthomorphism (`OrthoSigma256`, used in `FAEST-Areion-EM2-256{s,f}`)**:
  ```text
  K2 = sigma(K1_L || K1_R) = K1_R || (K1_L ⊕ K1_R)
  C  = P2_256(P1_256(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2
  ```
  Since `sigma^2 ⊕ sigma ⊕ id = 0`, all three whitening masks `(K1, K2, K1 ⊕ K2)` have full `GF(2)` rank `256 / 256` with zero multiplication gates.

#### The 288-S-Box Round-9 Free-Witness Theorem
Each round `r` (`0 <= r < 10`) of `Areion-256` updates the 16-byte active branch `A_r` and passive branch `B_r` via two 16-byte S-box layers (`32` S-boxes/round, `320` S-boxes total):
```text
A_next_r = ShiftRows(SubBytes(A_r))
U_r      = MixColumns(A_next_r) ⊕ RC[r]
B_next_r = B_r ⊕ MixColumns(ShiftRows(SubBytes(U_r)))
```
Because `ShiftRows` and `MixColumns` are invertible `GF(2)`-linear maps, recording the 32-byte post-round state `(A_next_r, B_next_r)` for rounds `r = 0..8` (`9 × 32 = 288` bytes = `2,304` bits) fixes both the input `(x0^(9), x1^(9)) = (A_next_8, B_next_8)` to Round 9 and, via the public boundary equation `(x0^(10), x1^(10)) = C ⊕ K2`, the output `(A_next_9, B_next_9)` of Round 9 with **zero committed witness bits in Round 9 (`32` free S-boxes = `256` bits saved)**:
```text
S^(r,1) = InvShiftRows(A_next_r)
X^(r,2) = MixColumns(A_next_r) ⊕ RC[r]
S^(r,2) = InvShiftRows(InvMixColumns(B_r ⊕ B_next_r))
```
In 20-round `FAEST-Areion-EM2-256`, committing `576` witness bytes (`288 B` for `P1` + `288 B` for `P2`) similarly determines all `640` S-boxes (`64` free S-boxes = `512` bits saved).

#### Coupled Degree-2 `QuickSilver` S-Box Equations over `GF(2^8)`
For every S-box input byte `X` and output byte `S = Affine(X^254)`, let `Y = GF256AffineInv(S) = X^254` in `GF(2^8) = GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (`0x11B`). The naive relation `X * Y ⊕ 1 = 0` fails when `X = 0x00` (`S = 0x63`, `Y = 0x00`), whereas a single degree-2 relation `Sq(X) * Y ⊕ X = 0` admits `255` spurious solutions `(X = 0x00, S != 0x63)`. `areion-pq` enforces the coupled bilinear pair:
```text
C1(X, S) = GF256Mul(GF256Sq(X), Y) ⊕ X = 0
C2(X, S) = GF256Mul(GF256Sq(Y), X) ⊕ Y = 0
```
Since `GF256Sq` and `GF256AffineInv` are `GF(2)`-linear on bit wires, `C1` and `C2` are quadratic (`degree 2`) in the committed VOLE bit tags and achieve `100%` completeness (`256 / 256` valid pairs) and `100%` soundness (`0 / 65,280` invalid pairs accepted; see [`analysis/README.md` (Section B)](analysis/README.md#b-quicksilver-gf28-degree-2-s-box-completeness-and-soundness)).

#### Parameter Sets & Comparison with `FAEST-256` and `FAEST-EM-256` (`Rijndael-256`)

| Scheme / Parameter Set | Underlying OWF | S-Boxes (Free) | Witness L (Bytes / Bits) | GGM Trees (tau) | PK (B) | SK (B) | Signature (B) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **FAEST-Areion-128s** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 304 B (2,432 b) | 13 | 48 | 64 | **6,448** |
| **FAEST-Areion-128f** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 304 B (2,432 b) | 16 | 48 | 64 | **7,456** |
| **FAEST-Areion-256s** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 320 B (2,560 b) | 26 | 64 | 96 | **18,208** |
| **FAEST-Areion-256f** | 10r Areion-256 (MulOrtho256) | 320 (32 free) | 320 B (2,560 b) | 32 | 64 | 96 | **20,512** |
| **FAEST-Areion-EM2-256s** | 20r Areion-EM2-256 (OrthoSigma256) | 640 (64 free) | 608 B (4,864 b) | 26 | 64 | 96 | **25,696** |
| **FAEST-Areion-EM2-256f** | 20r Areion-EM2-256 (OrthoSigma256) | 640 (64 free) | 608 B (4,864 b) | 32 | 64 | 96 | **30,368** |
| FAEST-EM-256 (NIST Round 2) | 14r Rijndael-256 | 448 (0 free) | 480 B (3,840 b) | 32 | 64 | 96 | ~25,100 |
| FAEST-256 (NIST Round 2) | 2 × 14r AES-256 + KeySched | 500 (0 free) | 512 B (4,096 b) | 32 | 64 | 96 | ~26,700 |

Compared to 14-round `Rijndael-256` (`FAEST-EM-256`, `480 B` witness) and `FAEST-256` (`512 B` witness), `FAEST-Areion-256{s,f}` reduces the committed witness length by **33.3%** and **37.5%** (`320 B` total: `32 B` key + `288 B` S-box witness) while executing without cross-lane `PSHUFB` / `VTBL` byte shuffles.

---

### 2. Track 2: `SLH-DSA-Areion` (`NIST FIPS 205` Stateless Hash-Based Signatures)

`SLH-DSA-Areion` instantiates the `NIST FIPS 205` (`SPHINCS+`) framework with `Areion-256` and `Areion-512` primitives:

1. **One-Time Seed Expansion (`SLHExpandSeed128` / `SLHExpandSeed256`)**: Expands `PK.seed` into a 64-byte public key schedule `K_pub = K_pub1 || K_pub2` via `(DM256(PK.seed), P2_256(PK.seed) ⊕ PK.seed)` and `SK.seed` into a 64-byte secret key schedule `K_sk`.
2. **Clamped-Capacity `DM512` Tweakable Hashes (Profile I — `SLHF128`, `SLHF256`, `SLHH128`, `SLHH256`, `SLHTl128`, `SLHTl256`)**:
   A naive feed-forward construction `F_naive(K_pub, ADRS, M1) = TEMEncrypt256(K_pub, ADRS, M1) ⊕ M1 = DM256(M1 ⊕ W(ADRS))` suffers total tweak cancellation (`quotient rank = 0 / 256`), allowing a 1-query multi-target collision `M1' = M1 ⊕ W(ADRS) ⊕ W(ADRS')`. Instead:
   - **`SLHF256` (`DM512-Clamped`)** evaluates `DM512((ADRS ⊕ K_pub1) || (M1 ⊕ K_pub2))`, clamping the 256-bit whitened address `ADRS ⊕ K_pub1` in the left 32-byte capacity half of `P1_512` (`quotient rank = 256 / 256`).
   - **`SLHF128` and `SLHH128`** pack `(PK.seed || ADRS || M1) ⊕ K_pub` and `(PK.seed || SLHCompactADRS(ADRS) || M1 || M2) ⊕ K_pub` into a single `DM512` call, where `SLHCompactADRS` extracts all 16 active `FIPS 205` address bytes (`GF(2)` rank `128 / 128`).
3. **Middle-Tweak `TEM` Tweakable Hash (Profile II — `SLHFTEM256` for `SLH-DSA-Areion-TEM-256f`)**:
   ```text
   SLHFTEM256(K_pub, ADRS, M1) = TEMEncrypt256(K_pub, M1, ADRS) ⊕ M1
                               = P1_256(ADRS ⊕ W(M1)) ⊕ W(M1) ⊕ M1,   W(M1) = P2_256(M1 ⊕ K_pub2) ⊕ K_pub1
   ```
   Feeding `M1` through `P2_256` as the nonlinear tweak mask while encrypting `ADRS` inside `P1_256` decouples `ADRS` from the outer feed-forward `⊕ W(M1) ⊕ M1` (`quotient rank = 256 / 256`; see [`analysis/README.md` (Section D)](analysis/README.md#d-slh-dsa-areion-tweak-cancellation-rank-audit-and-ipm-multi-target-bounds)).
4. **4-Way Batched `WOTS+` Secret-Key PRFs (`SLHPRF256x4`)**: Evaluates `SoEM256x4` across 4 `WOTS+` chain addresses in parallel.

#### Parameter Sets & Comparison with `NIST FIPS 205` (`SLH-DSA-SHA2` / `SLH-DSA-SHAKE`)

| Parameter Set | Category | n (B) | (h, d, h', a, k, len) | PK (B) | SK (B) | Signature (B) | Tweakable Chain Hash F |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **SLH-DSA-Areion-128f** | Cat 1 | 16 | (66, 22, 3, 6, 33, 35) | 32 | 64 | **17,088** | 1 × 15r DM512 (60 AES insts) |
| **SLH-DSA-Areion-128s** | Cat 1 | 16 | (63, 7, 9, 12, 14, 35) | 32 | 64 | **7,856** | 1 × 15r DM512 (60 AES insts) |
| **SLH-DSA-Areion-256f** | Cat 5 | 32 | (68, 17, 4, 9, 35, 67) | 64 | 128 | **49,856** | 1 × 15r DM512-Clamped (60 AES insts) |
| **SLH-DSA-Areion-256s** | Cat 5 | 32 | (64, 8, 8, 14, 22, 67) | 64 | 128 | **29,792** | 1 × 15r DM512-Clamped (60 AES insts) |
| **SLH-DSA-Areion-TEM-256f** | Cat 5 | 32 | (68, 17, 4, 9, 35, 67) | 64 | 128 | **49,856** | 1 × TEM-MiddleTweak (40 AES insts) |
| SLH-DSA-SHA2-128f / 256f | Cat 1 / 5 | 16 / 32 | FIPS 205 standard | 32 / 64 | 64 / 128 | 17,088 / 49,856 | 64r SHA-256 / 80r SHA-512 |
| SLH-DSA-SHAKE-128f / 256f | Cat 1 / 5 | 16 / 32 | FIPS 205 standard | 32 / 64 | 64 / 128 | 17,088 / 49,856 | 24r Keccak-f[1600] (136 B rate) |

---

### 3. Track 3: `Areion-HPKE` & `Areion-TEM2-SIV` Wide-Block AEAD

1. **`KDFExpand`**: Absorbs variable-length `secret` and `context` blocks through a domain-separated `DM512` sponge (`32 B` rate, `32 B` capacity), derives a 128-byte `SoEM512` key via `P1_256` and `P2_256`, and expands arbitrary-length key material at 256 bytes per iteration using 4-way `SoEM512x4`.
2. **`Areion-TEM2-SIV` (`TEM2SIVEncrypt*` / `TEM2SIVDecrypt*`)**:
   - **SIV Authentication (`tem2SIVComputeTag`)**: Absorbs the 32-byte `nonce`, `ad`, and `plaintext` in 256-byte (`4 × 64 B`) chunks via 4-way `SoEM512x4` with per-block counter and domain separation, finalized by `DM512` into a 32-byte (256-bit) synthetic IV `tag`.
   - **Wide-Block Encryption**: Encrypts full 64-byte (512-bit) blocks via 4-way `TEM2Encrypt512x4` / `TEM2Decrypt512x4` tweaked by `tag || nonce[0:16] || block_counter || domain` (and any partial tail `< 64 B` via `SoEM512`). Because `SoEM512` and `TEM2-512` operate on 512-bit states over independent `(P1_512, P2_512)`, `Areion-TEM2-SIV` achieves **Beyond-Birthday-Bound (BBB) security up to `2^341.3` classical queries (`2^170.7` quantum queries)** and full 256-bit nonce-misuse resistance (MRAE).
3. **Post-Quantum Hybrid Public-Key Encryption (`HPKESealMLKEM768` / `HPKEOpenMLKEM768`)**: Encapsulates a 32-byte shared secret using `ML-KEM-768` (`NIST FIPS 203`), derives a 128-byte DEM key and 32-byte base nonce via `HPKEDeriveKeys`, and seals/opens payloads with `Areion-TEM2-SIV`.

| AEAD Construction | Block Size | Key Size | Nonce / Tag | Classical Bound | Quantum Bound | Nonce-Misuse Behavior |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| AES-256-GCM (SP 800-38D) | 128 b | 256 b | 96 b / 128 b | 2^64.0 | 2^32.0 | Catastrophic (GHASH key recovery + stream reuse) |
| AES-256-GCM-SIV (RFC 8452) | 128 b | 256 b | 96 b / 128 b | 2^64.0 | 2^32.0 | 128-bit MRAE (capped by 128-bit block birthday bound) |
| **Areion-TEM2-SIV** | **512 b** | **1024 b** | **256 b / 256 b** | **2^341.3 (2n/3)** | **2^170.7** | **Full 256-bit SIV + 512-bit wide-block TPRP MRAE** |

---

## Hardware Acceleration

At package initialization, `areion-pq` probes CPU capabilities (`cpu_amd64.go`, `cpu_arm64.go`) and synchronizes its active tier with `github.com/everanium/areion`:

| Tier | Architectures | Instructions Used | Accelerated Primitives |
| :--- | :--- | :--- | :--- |
| **`avx512`** | Intel Ice Lake, Tiger Lake, Rocket Lake, Xeon Ice Lake-SP+; AMD Zen 4+ (`AVX-512F/DQ/BW/VL + VAES + VPCLMULQDQ`) | `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXORQ`, `VMOVDQU64` | 512-bit ZMM `VOLE` row XOR (`voleXorRowAVX512Asm`), 4-way ZMM `SoEM{256,512}x4` & `TEM2{Encrypt,Decrypt}512x4`, VEX `ExtractWitness256` & `GF128{Mul,PolyMAC}` |
| **`vaesavx2`** | Intel Alder Lake+; AMD Zen 3 (`AVX2 + VAES + VPCLMULQDQ`) | `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXOR`, `VMOVDQU` | 256-bit YMM `VOLE` row XOR (`voleXorRowAVX2Asm`), 4-way YMM `SoEM{256,512}x4` & `TEM2{Encrypt,Decrypt}512x4`, VEX `ExtractWitness256` & `GF128{Mul,PolyMAC}` |
| **`vex`** | Intel Sandy Bridge+, AMD Bulldozer+ (`AVX + AES-NI + PCLMULQDQ`) | 3-operand VEX `VAESENC`, `VAESENCLAST`, `VPCLMULQDQ`, `VPXOR`, `VPSRLDQ`, `VPSLLDQ` | Zero-copy VEX `areion256ExtractWitnessVexAsm`, `gf128MulVPCLMULAsm`, `gf128PolyMACVPCLMULAsm`, SSE2 `VOLE` row XOR |
| **`aesni`** | Intel Westmere+ (`AES-NI + PCLMULQDQ` without `AVX`) | Legacy 2-operand `AESENC`, `AESENCLAST`, `PCLMULQDQ`, `PXOR`, `PSRLDQ`, `PSLLDQ` | `areion256ExtractWitnessAsm`, `gf128MulPCLMULAsm`, `gf128PolyMACPCLMULAsm`, `voleXorRowSSE2Asm` |
| **`arm64`** | ARMv8 Cryptographic Extension, Apple Silicon, AWS Graviton (`NEON + AES + PMULL`) | `AESE`, `AESMC`, `VPMULL`, `VPMULL2`, `VEXT`, `VEOR` | `areion256ExtractWitnessAsm`, `gf128MulPMULLAsm`, `gf128PolyMACPMULLAsm`, 64-byte unrolled `voleXorRowNEONAsm` |
| **`purego`** | All architectures | Constant-time 64-bit bitsliced Boyar-Peralta S-boxes & maskless `GF(2^128)` arithmetic | Portable constant-time software implementations across all primitives |

> **Register and stack zeroization:** Every hardware assembly routine in `areion_pq_amd64.s` and `areion_pq_arm64.s` executes with a 0-byte stack frame (`NOSPLIT`) and clears all touched vector registers (`PXOR` / `VPXOR` / `VPXORD` + `VZEROUPPER` on `x86-64`; `VEOR` on `V0..V31` on `arm64`) and scratch general-purpose registers (`XORQ` on `x86-64`; `MOVD ZR` on `arm64`) before returning. Composite Go routines scrub local buffers via `clear(...)` + `runtime.KeepAlive(...)`, wipe their 1,024-byte software stack frame (`wipeSoftwareStack`), and clobber volatile registers (`clobberScratchGPRs`). Verified across all tiers by `TestFusedKernelsLeaveNoSecretInFrame` (`areion_pq_zeroize*_test.go`).

---

## Benchmarks

### 1. Intel® Core™ i7-11700K @ 3.60GHz (Rocket Lake, x86-64)

3-run averaged throughput measured across all 5 execution tiers on the same physical CPU (`f = 3.60 GHz`):

#### Finite-Field, Witness Extraction, KDF & Wide-Block AEAD Primitives (MB/s, ns/op)

| Operation | `purego` | `aesni` | `vex` | `vaesavx2` | `avx512` | `c/B` (best) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`GF128Mul` (16 B)** | 63.4 (252.63 ns) | 3,356.4 (4.77 ns) | 3,868.1 (4.14 ns) | 3,865.9 (4.14 ns) | 3,893.9 (4.11 ns) | 0.92 c/B |
| **`GF128PolyMAC` (16 blocks, 256 B)** | 30.1 (8,521.00 ns) | 2,505.8 (102.17 ns) | 2,513.9 (101.83 ns) | 2,541.5 (100.72 ns) | 2,517.2 (101.67 ns) | 1.42 c/B |
| **`ExtractWitness256` (288 B)** | 241.5 (1,193.33 ns) | 14,638.8 (19.68 ns) | 14,917.9 (19.32 ns) | 14,834.9 (19.42 ns) | 15,070.4 (19.11 ns) | 0.24 c/B |
| **`VerifyWitness256` (288 B)** | 22.2 (12,989.67 ns) | 8,349.9 (34.49 ns) | 8,000.1 (36.02 ns) | 8,036.7 (35.84 ns) | 8,175.3 (35.23 ns) | 0.43 c/B |
| **`ExtractWitnessEM2_256` (576 B)** | 240.9 (2,391.67 ns) | 15,067.5 (38.23 ns) | 14,817.2 (38.94 ns) | 15,220.4 (37.85 ns) | 15,034.8 (38.32 ns) | 0.24 c/B |
| **`VerifyWitnessEM2_256` (576 B)** | 22.2 (25,946.67 ns) | 7,801.9 (73.83 ns) | 7,504.7 (76.75 ns) | 7,634.6 (75.48 ns) | 7,626.5 (75.56 ns) | 0.46 c/B |
| **`KDFExpand` (1,024 B)** | 38.3 (26,725.33 ns) | 1,621.9 (632.10 ns) | 1,680.6 (609.80 ns) | 2,165.2 (472.93 ns) | 2,103.8 (486.90 ns) | 1.66 c/B |
| **`TEM2SIVEncrypt` (4,096 B)** | 18.8 (217,994.33 ns) | 697.3 (5,875.00 ns) | 707.4 (5,791.33 ns) | 1,086.2 (3,771.33 ns) | 1,202.2 (3,407.33 ns) | 2.99 c/B |
| **`TEM2SIVDecrypt` (4,096 B)** | 18.2 (225,308.33 ns) | 490.4 (8,355.33 ns) | 503.0 (8,143.33 ns) | 794.7 (5,154.33 ns) | 983.0 (4,168.67 ns) | 3.66 c/B |

#### Post-Quantum Signatures: `FAEST-Areion` & `SLH-DSA-Areion` (ops/s, ns/op)

| Operation | `purego` | `aesni` | `vex` | `vaesavx2` | `avx512` | Speedup vs `purego` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`FAESTSign128f`** | 23.1 (43,242,788 ns) | 465.3 (2,149,089 ns) | 494.1 (2,024,076 ns) | 551.4 (1,813,532 ns) | 609.9 (1,639,488 ns) | 26.4× |
| **`FAESTVerify128f`** | 24.0 (41,718,782 ns) | 505.6 (1,978,000 ns) | 517.0 (1,934,255 ns) | 576.3 (1,735,250 ns) | 607.8 (1,645,204 ns) | 25.4× |
| **`FAESTSign256f`** | 9.6 (103,877,138 ns) | 223.6 (4,472,561 ns) | 223.7 (4,471,005 ns) | 257.8 (3,879,216 ns) | 270.3 (3,700,216 ns) | 28.1× |
| **`FAESTVerify256f`** | 9.8 (101,848,166 ns) | 216.0 (4,628,742 ns) | 216.1 (4,628,347 ns) | 244.4 (4,092,364 ns) | 257.9 (3,877,479 ns) | 26.3× |
| **`FAESTEM2Sign256f`** | 6.0 (166,382,436 ns) | 139.0 (7,192,466 ns) | 137.9 (7,250,257 ns) | 163.7 (6,109,838 ns) | 176.7 (5,659,507 ns) | 29.4× |
| **`FAESTEM2Verify256f`** | 5.9 (168,220,966 ns) | 143.1 (6,986,787 ns) | 146.8 (6,813,240 ns) | 169.4 (5,903,627 ns) | 187.3 (5,339,351 ns) | 31.5× |
| **`SLHDSASign128f`** | 5.3 (188,266,847 ns) | 256.5 (3,898,049 ns) | 256.8 (3,893,755 ns) | 258.4 (3,870,171 ns) | 259.3 (3,856,919 ns) | 48.8× |
| **`SLHDSAVerify128f`** | 88.6 (11,286,195 ns) | 4,165.9 (240,045 ns) | 4,076.8 (245,290 ns) | 4,136.9 (241,724 ns) | 4,140.7 (241,507 ns) | 47.0× |
| **`SLHDSASign256f`** | 3.1 (318,086,498 ns) | 143.5 (6,969,872 ns) | 145.2 (6,885,496 ns) | 166.0 (6,024,004 ns) | 158.9 (6,291,604 ns) | 52.8× |
| **`SLHDSAVerify256f`** | 62.3 (16,063,318 ns) | 3,374.1 (296,372 ns) | 3,362.1 (297,432 ns) | 3,344.7 (298,979 ns) | 3,343.3 (299,103 ns) | 54.2× |
| **`SLHDSATEMSign256f`** | 1.5 (656,406,122 ns) | 69.3 (14,420,642 ns) | 69.7 (14,344,520 ns) | 68.8 (14,530,767 ns) | 69.5 (14,383,040 ns) | 45.8× |
| **`SLHDSATEMVerify256f`** | 53.7 (18,636,303 ns) | 2,421.0 (413,055 ns) | 2,442.8 (409,364 ns) | 2,414.4 (414,183 ns) | 2,447.2 (408,630 ns) | 45.6× |

On Intel® Core™ i7-11700K, `SLHDSAVerify128f` completes in **`240.0 us` (`4,166 ops/s`)** and `SLHDSAVerify256f` in **`296.4 us` (`3,374 ops/s`)**, while `FAESTSign128f` / `FAESTVerify128f` run in **`1.64 ms` / `1.65 ms`**, `FAESTSign256f` / `FAESTVerify256f` in **`3.70 ms` / `3.88 ms`**, `KDFExpand` reaches **`2,165.2 MB/s`** (`1.66 c/B`), and `TEM2SIVEncrypt` reaches **`1,202.2 MB/s`** (`2.99 c/B`) on `avx512`.

### 2. AWS Graviton 4 (`c8g.4xlarge`, Neoverse-V2, 16 vCPUs, ARM64)

3-run averaged throughput measured on AWS Graviton 4 (`purego` bitsliced fallback vs `arm64` ARMv8 Cryptographic Extension at `f = 2.80 GHz`):

#### Finite-Field, Witness Extraction, KDF & Wide-Block AEAD Primitives (MB/s, ns/op)

| Operation | `purego` | `arm64` | `c/B` (`arm64`) |
| :--- | :---: | :---: | :---: |
| **`GF128Mul` (16 B)** | 75.8 (211.13 ns) | 3,657.8 (4.37 ns) | 0.77 c/B |
| **`GF128PolyMAC` (16 blocks, 256 B)** | 43.7 (5,855.67 ns) | 1,714.0 (149.33 ns) | 1.63 c/B |
| **`ExtractWitness256` (288 B)** | 236.7 (1,217.00 ns) | 6,864.9 (41.95 ns) | 0.41 c/B |
| **`VerifyWitness256` (288 B)** | 22.2 (12,960.67 ns) | 4,735.7 (60.82 ns) | 0.59 c/B |
| **`ExtractWitnessEM2_256` (576 B)** | 235.6 (2,445.00 ns) | 7,484.0 (76.97 ns) | 0.37 c/B |
| **`VerifyWitnessEM2_256` (576 B)** | 22.1 (26,063.00 ns) | 4,917.2 (117.13 ns) | 0.57 c/B |
| **`KDFExpand` (1,024 B)** | 37.7 (27,178.67 ns) | 911.2 (1,124.00 ns) | 3.07 c/B |
| **`TEM2SIVEncrypt` (4,096 B)** | 18.5 (221,643.67 ns) | 490.7 (8,348.00 ns) | 5.71 c/B |
| **`TEM2SIVDecrypt` (4,096 B)** | 17.4 (235,578.00 ns) | 467.7 (8,757.00 ns) | 5.99 c/B |

#### Post-Quantum Signatures: `FAEST-Areion` & `SLH-DSA-Areion` (ops/s, ns/op)

| Operation | `purego` | `arm64` | Speedup vs `purego` |
| :--- | :---: | :---: | :---: |
| **`FAESTSign128f`** | 24.0 (41,719,614 ns) | 490.4 (2,039,335 ns) | 20.5× |
| **`FAESTVerify128f`** | 24.4 (41,046,465 ns) | 508.7 (1,965,670 ns) | 20.9× |
| **`FAESTSign256f`** | 9.6 (104,172,061 ns) | 210.2 (4,758,377 ns) | 21.9× |
| **`FAESTVerify256f`** | 9.8 (101,796,375 ns) | 217.6 (4,595,091 ns) | 22.2× |
| **`FAESTEM2Sign256f`** | 6.1 (163,742,096 ns) | 134.9 (7,413,393 ns) | 22.1× |
| **`FAESTEM2Verify256f`** | 6.2 (160,169,666 ns) | 143.0 (6,992,543 ns) | 22.9× |
| **`SLHDSASign128f`** | 5.3 (188,773,229 ns) | 149.7 (6,678,451 ns) | 28.3× |
| **`SLHDSAVerify128f`** | 85.3 (11,724,602 ns) | 2,474.8 (404,078 ns) | 29.0× |
| **`SLHDSASign256f`** | 3.1 (326,740,950 ns) | 98.4 (10,167,592 ns) | 32.1× |
| **`SLHDSAVerify256f`** | 60.2 (16,601,636 ns) | 2,127.1 (470,130 ns) | 35.3× |
| **`SLHDSATEMSign256f`** | 1.5 (674,148,845 ns) | 38.1 (26,276,207 ns) | 25.7× |
| **`SLHDSATEMVerify256f`** | 51.0 (19,622,539 ns) | 1,335.4 (748,859 ns) | 26.2× |

On AWS Graviton 4 (`arm64`), `SLHDSAVerify128f` completes in **`404.1 us` (`2,475 ops/s`)** and `SLHDSAVerify256f` in **`470.1 us` (`2,127 ops/s`)**, while `FAESTSign128f` / `FAESTVerify128f` run in **`2.04 ms` / `1.97 ms`** and `FAESTSign256f` / `FAESTVerify256f` in **`4.76 ms` / `4.60 ms`**.

---

## Cryptanalytic & Algebraic Verification Suite (`analysis/`)

[`analysis/README.md`](analysis/README.md) contains 9 reproducible symbolic, algebraic, and empirical verification tools (`rank`, `sbox_qs`, `ortho`, `tweak`, `bounds`, `witness`, `slh`, `vole`, `integral`) validating every structural claim in this package:

- **`rank` (`py/round9_witness_rank.py`)**: Symbolic `GF(2)` Gaussian elimination proving full Jacobian rank `d(Y)/d(w) = 2304 / 2304` and `d(X,Y)/d(K1,w) = 2560 / 2560` for 10-round `Areion-256` (`32` free S-boxes in Round 9), `4608 / 4608` for 20-round `Areion-EM2-256` (`64` free S-boxes), and `5376 / 5376` for 15-round `Areion-512` (`48` free S-boxes + `128` linear check bits).
- **`sbox_qs` (`py/quicksilver_sbox_soundness.py`)**: Exhaustive check over all `256 × 256 = 65,536` byte pairs `(X, S)` in `GF(2^8)` proving `100%` completeness (`256 / 256`) and `100%` soundness (`65,280 / 65,280` invalid pairs rejected) of the coupled degree-2 `QuickSilver` equations.
- **`ortho` (`py/orthomorphism_bijectivity.py`)**: `GF(2)^256` determinant and rank verification (`rank(L) = 256 / 256`, `rank(I ⊕ L) = 256 / 256`) for `OrthoSigma256` and clamped `MulOrtho256`.
- **`tweak` (`py/slh_tweak_separation.py`) & `slh` (`go/slh_collision.go`)**: Quotient-space rank proof and `10,000`-trial empirical demonstration of `100%` tweak cancellation in naive feed-forward `TEM` vs `0 / 10,000` collisions and full `256 / 256` tweak capacity rank in `SLHF256`, `SLHF128`, `SLHH128`, and `SLHFTEM256`.
- **`witness` (`go/witness_check.go`), `vole` (`go/vole_check.go`), & `integral` (`c/pq_integral.c`)**: `100,000` random witness extractions, `46,080` exhaustive single-bit witness corruptions (`100%` rejected), `1,000,000` hardware `PCLMULQDQ` `QuickSilver` gate checks, and Order-1 / Order-2 `AES-NI` `Lambda`-set integral dissolution tests.

---

## Reproduce

### 1. Run Complete Test Suite
```bash
# Run all unit tests, cross-tier parity tests, tamper checks, and zeroization tests:
go test -v -count=1 ./...

# Verify clean vet and cross-architecture compilation:
go vet ./...
GOARCH=arm64 go vet ./...
go vet -tags purego ./...
```

### 2. Test Specific Execution Tiers & Cross-Architecture QEMU Targets
The environment variable `AREION_PQ_FORCE_TIER` forces the active execution tier:
```bash
# Portable Go bitsliced fallback:
AREION_PQ_FORCE_TIER=purego go test -v -count=1 ./...

# AES-NI + PCLMULQDQ (128-bit legacy SSE XMM):
AREION_PQ_FORCE_TIER=aesni go test -v -count=1 ./...

# VEX (128-bit 3-operand VEX XMM, AVX + AES-NI + PCLMULQDQ):
AREION_PQ_FORCE_TIER=vex go test -v -count=1 ./...

# 256-bit YMM Vector AES (AVX2 + VAES + VPCLMULQDQ):
AREION_PQ_FORCE_TIER=vaesavx2 go test -v -count=1 ./...

# 512-bit ZMM Vector AES (AVX-512 + VAES + VPCLMULQDQ):
AREION_PQ_FORCE_TIER=avx512 go test -v -count=1 ./...

# ARMv8 Cryptographic Extension (on arm64 hosts or under qemu-aarch64-static):
GOARCH=arm64 go test -c -o /tmp/areion_pq_arm64.test .
qemu-aarch64-static /tmp/areion_pq_arm64.test -test.v
```

### 3. Run Benchmarks
```bash
# Auto-selected tier:
go test -run=^none -bench=. -benchmem ./...

# Benchmark individual tiers:
AREION_PQ_FORCE_TIER=purego go test -run=^none -bench=. -benchtime=500ms .
AREION_PQ_FORCE_TIER=aesni go test -run=^none -bench=. -benchtime=500ms .
AREION_PQ_FORCE_TIER=vex go test -run=^none -bench=. -benchtime=500ms .
AREION_PQ_FORCE_TIER=vaesavx2 go test -run=^none -bench=. -benchtime=500ms .
AREION_PQ_FORCE_TIER=avx512 go test -run=^none -bench=. -benchtime=500ms .
AREION_PQ_FORCE_TIER=arm64 go test -run=^none -bench=. -benchtime=500ms .
```

### 4. Run Cryptanalytic & Algebraic Verification Suite
```bash
python3 analysis/run.py list
python3 analysis/run.py all --quick
```
See [`analysis/README.md`](analysis/README.md) for detailed results and logs (`analysis/results/*.txt`).

---

## Usage Example

```go
package main

import (
	"crypto/mlkem"
	"fmt"

	areionpq "github.com/everanium/areion-pq"
)

func main() {
	// 0. Optional FIPS 140-3 Cryptographic Algorithm Self-Test (CAST)
	if err := areionpq.SelfTest(); err != nil {
		panic(err)
	}

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

---

## References

1. **Areion: Highly-Efficient Permutations and Its Applications to Hash Functions for Short Input**
   Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki Nakahashi, Kosei Sakamoto, Rentaro Shiba.
   *IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES)*, Volume 2023, Issue 2, pp. 115–154, [doi:10.46586/tches.v2023.i2.115-154](https://doi.org/10.46586/tches.v2023.i2.115-154); extended version [IACR ePrint 2023/794](https://eprint.iacr.org/2023/794).

2. **Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head (FAEST)**
   Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß, Emmanuela Orsini, Lawrence Roy, Peter Scholl.
   *CRYPTO 2023*, Part V, Lecture Notes in Computer Science, vol. 14085, pp. 581–615, [doi:10.1007/978-3-031-38554-4_19](https://doi.org/10.1007/978-3-031-38554-4_19), [IACR ePrint 2023/996](https://eprint.iacr.org/2023/996).

3. **QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field**
   Kang Yang, Pratik Sarkar, Chenkai Weng, Xiao Wang.
   *ACM CCS 2021*, pp. 2986–3001, [doi:10.1145/3460120.3484556](https://doi.org/10.1145/3460120.3484556), [IACR ePrint 2021/076](https://eprint.iacr.org/2021/076).

4. **Stateless Hash-Based Digital Signature Standard (SLH-DSA)**
   National Institute of Standards and Technology (NIST).
   *Federal Information Processing Standards Publication 205 (FIPS 205)*, August 2024, [doi:10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205).

5. **Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)**
   National Institute of Standards and Technology (NIST).
   *Federal Information Processing Standards Publication 203 (FIPS 203)*, August 2024, [doi:10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203).

6. **How to Build Pseudorandom Functions from Public Random Permutations (SoEM22)**
   Yu Long Chen, Eran Lambooij, Bart Mennink.
   *CRYPTO 2019*, Part I, LNCS vol. 11692, pp. 266–293, [IACR ePrint 2019/554](https://eprint.iacr.org/2019/554).

7. **Tweaking Even-Mansour Ciphers**
   Benoît Cogliati, Rodolphe Lampe, Yannick Seurin, *CRYPTO 2015*, Part I, LNCS vol. 9215, pp. 189–208; and Avijit Dutta, **Minimizing the Two-Round Tweakable Even-Mansour Cipher**, *ASIACRYPT 2020*, Part I, LNCS vol. 12491, pp. 601–629.

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Copyright (c) 2026 Andrey Kuvshinov.
