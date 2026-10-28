# Cryptanalytic and Algebraic Analysis of `areion-pq`

This directory contains the reproducible algebraic, structural, and empirical verification suite for the three post-quantum and beyond-birthday-bound cryptographic tracks of `areion-pq`:

1. **Track 1 (`FAEST-Areion`):** Zero-knowledge `VOLE-in-the-Head` (`VOLEitH`) and `QuickSilver` degree-2 polynomial signatures built on the 10-round `Areion-256` one-way function (`TEM-Linear` with `K2 = MulOrtho256(T, K1)` and 20-round `EM2-Ortho` with `K2 = OrthoSigma256(K1)`).
2. **Track 2 (`SLH-DSA-Areion`):** Stateless hash-based signatures (`NIST FIPS 205`) instantiated with domain-separated `Areion-512` Davies-Meyer (`DM512`), middle-tweak `Areion-256` Tweakable Even-Mansour (`TEM-MiddleTweak`), and `SoEM256` pseudorandom functions.
3. **Track 3 (`Areion-HPKE` & `Areion-TEM2-SIV`):** Hybrid post-quantum key encapsulation (`ML-KEM-768` + `AreionKDF`) and 512-bit wide-block nonce-misuse-resistant authenticated encryption (`SoEM512` SIV + `TEM2-512`).

Every check in `analysis/run.py` prints its verification summary to standard output; `--record` writes the deterministic reference logs to `analysis/results/<check>.txt`.

## Results

| Claim, within the stated model | Result | Check |
|---|---|---|
| **A.** **Free-Round Witness Theorem (`Areion-256`, `Areion-EM2-256`, `Areion-512`):** Recording `288` witness bytes (`2,304` bits, rounds `0..8`) in 10-round `Areion-256` fixes all `320` S-box input bytes `X^(r,l)` and all `320` inverse-affine S-box output bytes `Y^(r,l) = AffineInv(S^(r,l) ⊕ 0x63)` across all 10 rounds (`r = 0..9`) as exact `GF(2)`-affine functions of `(K1, w[0..287], M, C ⊕ K2)` with `0` witness degrees of freedom in Round 9 (`32` free S-boxes = `256` bits saved, `-10.0%`), full Jacobian rank `d(Y^(0..8))/d(w) = 2304 / 2304`, full key+witness rank `d(X, Y)/d(K1, w) = 2560 / 2560`, and Round 9 boundary rank `256 / 256`; in 20-round `Areion-EM2-256`, `576` witness bytes (`4,608` bits) determine all `640` S-boxes (`64` free S-boxes = `512` bits saved, Jacobian rank `4608 / 4608` and `4864 / 4864`); in 15-round `Areion-512`, `672` witness bytes (`5,376` bits, rounds `0..13`) determine all `720` S-boxes (`48` free S-boxes = `384` bits saved in Round 14 plus `128` passive-branch `GF(2)`-linear consistency equations `b'_14 = b_14 ⊕ MC(a'_14)`, Jacobian rank `5376 / 5376` and `512 / 512`) | holds | `rank`, `witness` |
| **B.** **`QuickSilver` `GF(2^8)` Degree-2 S-Box Completeness and Soundness:** Over all `256 x 256 = 65,536` byte pairs `(X, S)` in `GF(2^8) = GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (`0x11B`), the coupled degree-2 bilinear equations `C1(X, S) = Sq(X)*Y ⊕ X == 0` and `C2(X, S) = Sq(Y)*X ⊕ Y == 0` (with `Y = AffineInv(S ⊕ 0x63)`) achieve **100% completeness (`256 / 256` valid pairs pass, including `X = 0x00, S = 0x63 -> Y = 0x00`)** and **100% soundness (`0 / 65,280` invalid pairs pass; `65,280 / 65,280` rejected)**, whereas `X*Y ⊕ 1 == 0` fails completeness at `(0x00, 0x63)`, `C1` alone admits `255` spurious solutions `(X = 0x00, S != 0x63)`, and `C2` alone admits `1` spurious solution `S = 0x63` (`Y = 0`) for each `X != 0x00` (`255` invalid pairs); bit-level gate equations match field arithmetic on `256 / 256` unary and `65,536 / 65,536` bilinear inputs, and `GF(2^128)` VOLE homomorphic evaluation satisfies `B_V == A0 ⊕ A1*Delta` on `256 / 256` valid pairs and fails with `B_V ⊕ A0 ⊕ A1*Delta == C_bit * Delta^2 != 0` on all invalid pairs | holds | `sbox_qs`, `vole` |
| **C.** **Orthomorphism Bijectivity and OWF Key Uniqueness (`MulOrtho256`, `OrthoSigma256`):** Over `GF(2)^256`, both `OrthoSigma256(K) = (K_R, K_L ⊕ K_R)` (`L^2 ⊕ L ⊕ I == 0`, order `3`) and `MulOrtho256(T, K) = (GF128Mul(T_0, K_0), GF128Mul(T_1, K_1))` for all clamped `T_0, T_1 not in {0, 1}` (`T[0] \|= 0x02, T[16] \|= 0x02`) have exact `GF(2)` rank `rank(L) = 256 / 256` (`det(L) = 1`) and `rank(I ⊕ L) = 256 / 256` (`det(I ⊕ L) = 1`), whereas unclamped `T = (0, 0)` collapses `rank(L) = 0 / 256` and `T = (1, 1)` collapses `rank(I ⊕ L) = 0 / 256`; clamping `K2 = L(K1)` eliminates the `2^256` degenerate key space and `O(1)` 1-query forgery of unconstrained `(K1, K2)` while ensuring full `256 / 256` rank across all three `2-EM` whitening keys `(K1, L(K1), K1 ⊕ L(K1))` | holds | `ortho`, `vole` |
| **D.** **`SLH-DSA-Areion` Tweak-Cancellation Audit and Ideal Permutation Model (IPM) Bounds:** Naive feed-forward `F_naive(K_pub, ADRS, M1) = TEMEncrypt256(K_pub, ADRS, M1) ⊕ M1 = DM256(M1 ⊕ W(ADRS))` suffers total tweak cancellation (`quotient rank = 0 / 256` modulo `Span(M1)`), allowing a deterministic `O(1)` 1-query multi-target collision `M1' = M1 ⊕ W(ADRS) ⊕ W(ADRS')` across arbitrary distinct addresses (`10,000 / 10,000` empirical collisions); Profile I `SLHF256` (`DM512-Clamped`, `quotient rank = 256 / 256`), Category 1 `SLHF128` (`quotient rank = 384 / 384`), Category 1 `SLHH128` (`ADRS_compact` injective rank `128 / 128`, `quotient rank = 256 / 256`), and Profile II `SLHFTEM256` (`TEM-MiddleTweak`, `quotient rank = 256 / 256`) preserve full tweak capacity rank and yield `0 / 10,000` shift collisions | holds | `tweak`, `slh` |
| **E.** **Post-Quantum Witness, Signature, and Wide-Block AEAD Bounds:** `FAEST-Areion-256{s,f}` commits to `L_bytes = 320 B` (`2,560` bits, `320` S-boxes with `32` free), achieving a **`33.3%` witness reduction** vs 14-round `Rijndael-256` (`3,840` bits) and **`37.5%` reduction** vs `FAEST-256` (`4,096` bits), yielding `6,448 B` (`128s`), `7,456 B` (`128f`), `18,208 B` (`256s`), `20,512 B` (`256f`), `25,696 B` (`EM2-256s`), and `30,368 B` (`EM2-256f`) signatures; `SLH-DSA-Areion` matches `FIPS 205` signature sizes (`7,856 B` to `49,856 B`) while replacing 64/80-round sequential `SHA-2` with 15-round `Areion-512` (`60` hardware AES instructions per 64 B compression); `Areion-TEM2-SIV` provides `2^341.3` classical / `2^170.7` quantum BBB security and 512-bit wide-block MRAE protection | holds | `bounds` |
| **F.** **Empirical Witness Extraction, Avalanche, `QuickSilver` VOLE, and `Lambda`-Set Integral Verification:** `100,000` random `(M, K1, K2)` extractions on `P1`, `P2`, and `EM2` pass degree-2 `GF(2^8)` verification with `0` mismatches against `github.com/everanium/areion` and `100.0%` rejection across all `46,080` exhaustive 1-bit witness flips, `5,120` Round 8->9 boundary flips, `5,120` output `C` flips, `5,120` key `K1` flips, and `100,000` multi-bit corruptions; `SLHF128`, `SLHF256`, `SLHFTEM256`, `SLHH128`, `SLHH256`, `SLHPRF256`, and `TEM2-SIV` satisfy strict bitwise avalanche (`meanHW = 0.49997 .. 0.50003`, `maxChi2(255) <= 318.2`); `AES-NI` `Lambda`-set sums of orders 1 and 2 (`256` and `65,536` texts) confirm exact zero-sum balance through `r = 4..5` (`DM512`) and `r = 2..3` (`TEM256`) and full dissolution (`0` balanced bytes) from `r = 6` / `r = 4` through full rounds (`r = 15` / `r = 10`), while `1,000,000` hardware `PCLMULQDQ` `QuickSilver` VOLE gate evaluations pass with `0` errors | holds | `witness`, `slh`, `vole`, `integral` |

---

### A. Free-Round Witness Theorem (`Areion-256`, `Areion-EM2-256`, and `Areion-512`)

In `VOLE-in-the-Head` (`FAEST`) signatures, signature size scales linearly with the number of committed witness bits `L_bits = 8 * (k_bytes + w_bytes)`. Check `rank` (`py/round9_witness_rank.py`, `results/rank.txt`) constructs the exact symbolic `GF(2)` bit-level circuit for 10-round `Areion-256`, 20-round `Areion-EM2-256`, and 15-round `Areion-512`, representing every state wire as an exact `GF(2)`-affine bitmask over the public inputs `(M, C)`, round constants `RC`, secret key `K1`, and round witness bytes `w`.

#### 1. `Areion-256` (`10` rounds, `320` S-boxes -> `288` committed S-box bytes)

In round `r` (`0 <= r < 10`) of `Areion-256`, let `A_r` be the active 16-byte branch (`x0` for even `r`, `x1` for odd `r`) and `B_r` be the passive 16-byte branch (`x1` for even `r`, `x0` for odd `r`). The round transformation updates `(A_r, B_r) -> (A_next_r, B_next_r)` via two 16-byte S-box layers:

- **Layer 1 (`16` S-boxes):** `A_next_r = ShiftRows(SubBytes(A_r))` (`AESENCLAST(A_r, 0)`).
  Applying `InvShiftRows` recovers the 16 S-box outputs `S^(r,1) = SubBytes(A_r) = InvShiftRows(A_next_r)` as an exact `GF(2)`-linear permutation of `A_next_r`.
- **Layer 2 (`16` S-boxes):** `U_r = MixColumns(A_next_r) ⊕ RC[r]` (`AESENC(A_r, RC[r])`), and `B_next_r = B_r ⊕ MixColumns(ShiftRows(SubBytes(U_r)))`.
  Applying `InvShiftRows ∘ InvMixColumns` to `B_r ⊕ B_next_r` recovers the 16 S-box outputs `S^(r,2) = SubBytes(U_r) = InvShiftRows(InvMixColumns(B_r ⊕ B_next_r))` as an exact `GF(2)`-linear function of `(B_r, B_next_r)`, while the 16 S-box inputs `X^(r,2) = MixColumns(A_next_r) ⊕ RC[r]` are an exact `GF(2)`-affine function of `A_next_r`.

Consequently, when the witness `w[0..287]` (`288` bytes = `2,304` bits) records `(A_next_r, B_next_r)` for the first 9 rounds (`r = 0..8`), the state `(x0^(9), x1^(9)) = (A_next_8, B_next_8)` entering the final round `r = 9` (`A_9 = x1^(9)`, `B_9 = x0^(9)`) is already fixed in the witness, and the output of Round 9 is fixed by the boundary relation `(x0^(10), x1^(10)) = C ⊕ K2`:

- `A_next_9 = x1^(10) = (C ⊕ K2)[16:32]` (`0` witness bits required)
- `B_next_9 = x0^(10) = (C ⊕ K2)[0:16]` (`0` witness bits required)
- `X^(9,1) = x1^(9) = w_8[16:32]` and `S^(9,1) = InvShiftRows((C ⊕ K2)[16:32])`
- `X^(9,2) = MixColumns((C ⊕ K2)[16:32]) ⊕ RC[9]` and `S^(9,2) = InvShiftRows(InvMixColumns(w_8[0:16] ⊕ (C ⊕ K2)[0:16]))`

Gaussian elimination over `GF(2)` in `py/round9_witness_rank.py` confirms:

| Symbolic `GF(2)` Jacobian / Rank Metric | `Areion-256` (`10r`) | `Areion-EM2-256` (`20r`) | `Areion-512` (`15r`) |
| :--- | :---: | :---: | :---: |
| Total S-boxes across permutation(s) | `320` (`2,560` b) | `640` (`5,120` b) | `720` (`5,760` b) |
| Committed witness bytes `w` | `288 B` (`2,304` b) | `576 B` (`4,608` b) | `672 B` (`5,376` b) |
| Uncommitted free S-boxes in final round(s) | `32` (`256` b, `0` DOF) | `64` (`512` b, `0` DOF) | `48` (`384` b, `0` DOF) |
| Witness output Jacobian rank `d(Y) / d(w)` | `2304 / 2304` | `4608 / 4608` | `5376 / 5376` |
| Full key+witness Jacobian rank `d(X, Y) / d(K1, w)` | `2560 / 2560` | `4864 / 4864` | `5888 / 5888` |
| Final-round boundary rank w.r.t. `(w_last, C ⊕ K2)` | `256 / 256` | `512 / 512` | `512 / 512` |
| Concrete trace mismatches (`200` / `100` random runs) | `0` | `0` | `0` |

#### 2. `Areion-512` (`15` rounds, `720` S-boxes -> `672` committed S-box bytes + `128` linear check bits)

In each round `r` (`0 <= r < 15`) of `Areion-512` with word offset `o = r % 4` and `(a, b, c, d) = (x[o], x[(o+1)%4], x[(o+2)%4], x[(o+3)%4])`:

1. `a' = ShiftRows(SubBytes(a))` (`16` S-boxes; `S^(r,1) = InvShiftRows(a')`).
2. `b' = b ⊕ MixColumns(a')` (`0` new S-boxes: `b'` is an exact `GF(2)`-linear function of `(b, a')` in every round).
3. `u_r = ShiftRows(SubBytes(c))` and `d' = d ⊕ MixColumns(u_r)` (`16` S-boxes; `u_r = InvMixColumns(d ⊕ d')` and `S^(r,2) = InvShiftRows(u_r)` are exact `GF(2)`-linear functions of `(d, d')`).
4. `X^(r,3) = u_r ⊕ RC[r]` and `c' = MixColumns(ShiftRows(SubBytes(X^(r,3))))` (`16` S-boxes; `S^(r,3) = InvShiftRows(InvMixColumns(c'))`).

Each round `r = 0..13` therefore commits to `48` bytes `(a'_r, c'_r, d'_r)` (`14 x 48 = 672` bytes = `5,376` bits), while in Round 14 (`r = 14`), `(a'_14, b'_14, c'_14, d'_14)` is fixed by the unrotated output `C ⊕ K2`. All `48` S-boxes of Round 14 (`384` bits) require `0` witness bytes, and the passive branch `b'_14 ⊕ b_14 ⊕ MixColumns(a'_14) == 0` supplies `128` additional independent `GF(2)`-linear equations (`384 + 128 = 512 / 512` full boundary rank).

---

### B. `QuickSilver` `GF(2^8)` Degree-2 S-Box Completeness and Soundness

Every AES S-box evaluations `S = Affine(Inv_GF256(X)) ⊕ 0x63` over `GF(2^8) = GF(2)[z] / (z^8 + z^4 + z^3 + z + 1)` (`0x11B`) maps `X` to `Y = AffineInv(S ⊕ 0x63) = X^254`. Check `sbox_qs` (`py/quicksilver_sbox_soundness.py`, `results/sbox_qs.txt`) exhaustively evaluates all `256 x 256 = 65,536` byte pairs `(X, S)` against the coupled degree-2 bilinear equations:

- `C1(X, S) = Sq(X) * Y ⊕ X == 0` (`8` bit constraints)
- `C2(X, S) = Sq(Y) * X ⊕ Y == 0` (`8` bit constraints)

where `U = Sq_GF256(X)` and `W = Sq_GF256(Y)` are `GF(2)`-linear squaring maps in `GF(2^8)`:

- `u[0] = x[0] ⊕ x[4] ⊕ x[6]`
- `u[1] = x[4] ⊕ x[6] ⊕ x[7]`
- `u[2] = x[1] ⊕ x[5]`
- `u[3] = x[4] ⊕ x[5] ⊕ x[6] ⊕ x[7]`
- `u[4] = x[2] ⊕ x[4] ⊕ x[7]`
- `u[5] = x[5] ⊕ x[6]`
- `u[6] = x[3] ⊕ x[5]`
- `u[7] = x[6] ⊕ x[7]`

and degree-14 bilinear product bits `d[k] = XOR_{i+j=k} (a[i] & b[j])` reduce modulo `z^8 + z^4 + z^3 + z + 1` (`0x11B`) via `r6 = d[14]`, `r5 = d[13]`, `r4 = d[12]`, `r3 = d[11]`, `r2 = d[10] ⊕ r6`, `r1 = d[9] ⊕ r5 ⊕ r6`, `r0 = d[8] ⊕ r4 ⊕ r5`.

| Constraint System on `(X, S)` (`65,536` total byte pairs) | Valid Pairs Accepted (`/ 256`) | `(X=0x00, S=0x63)` Accepted | Invalid Pairs Accepted (`/ 65,280`) | Spurious Failure Mode |
| :--- | :---: | :---: | :---: | :--- |
| Naive `X * Y ⊕ 1 == 0` (`8` bits) | `255 / 256` | `FAIL` (`0 ⊕ 1 != 0`) | `0 / 65,280` | Rejects valid zero-input S-box transition `(0x00, 0x63)` |
| Single equation `C1(X, S) = Sq(X)*Y ⊕ X == 0` (`8` bits) | `256 / 256` | `PASS` | `255 / 65,280` | Accepts all `255` invalid pairs `(X = 0x00, S != 0x63 -> Y != 0)` |
| Single equation `C2(X, S) = Sq(Y)*X ⊕ Y == 0` (`8` bits) | `256 / 256` | `PASS` | `255 / 65,280` | Accepts `1` spurious solution `S = 0x63` (`Y = 0`) for every `X != 0x00` (`255` pairs) |
| **Coupled `(C1 == 0) & (C2 == 0)` (`16` bits)** | **`256 / 256` (`100%`)** | **`PASS`** | **`0 / 65,280` (`100%` sound)** | **None (`65,280 / 65,280` invalid pairs rejected)** |

Under `GF(2^128)` VOLE correlations `V(z) = Q(z) ⊕ val(z) * Delta` (`p_128(x) = x^128 + x^7 + x^2 + x + 1`, `0x87`), Prover's degree-2 polynomial coefficients `(A0, A1)` and Verifier's evaluation `B_V` obey the exact algebraic error law:

`B_V ⊕ A0 ⊕ (A1 * Delta) == C_bit * (Delta^2)`

which vanishes across all `16` bit constraints on `256 / 256` valid pairs and equals `Delta^2 != 0` on every active constraint bit of all `65,280` invalid pairs (`1,000 / 1,000` random VOLE trials verified in `sbox_qs`).

---

### C. Public-Tweak and Fixed-Key Orthomorphisms (`MulOrtho256`, `OrthoSigma256`)

In an Even-Mansour one-way function `C = P1(M ⊕ K1) ⊕ K2` (`1-EM`) or `C = P2(P1(M ⊕ K1) ⊕ K2) ⊕ K1 ⊕ K2` (`2-EM`), leaving `(K1, K2) in {0,1}^512` unconstrained creates `2^256` valid key pairs `(K1, K2)` per public `(M, C)` pair and admits a trivial `O(1)` 1-query key-recovery forgery: an attacker picks arbitrary `K1` and sets `K2 = P1(M ⊕ K1) ⊕ C`. Setting `K2 = K1` eliminates the extra key degrees of freedom in `1-EM`, but in `2-EM` causes the outer whitening key `K1 ⊕ K2` to vanish (`rank(I ⊕ L) = 0`).

To preserve both key uniqueness (`256` key bits) and non-degenerate whitening across all rounds, `K2 = L(K1)` must be a **`GF(2)`-linear orthomorphism** on `{0,1}^256`: both `L` and `I ⊕ L` (`K -> K ⊕ L(K)`) must be invertible (`rank(L) = 256 / 256, det(L) = 1` and `rank(I ⊕ L) = 256 / 256, det(I ⊕ L) = 1`). Check `ortho` (`py/orthomorphism_bijectivity.py`, `results/ortho.txt`) constructs the `256 x 256` `GF(2)` matrices for both library orthomorphisms:

| Orthomorphism / Key Mode | Key DOF | `rank(L)` (`det`) | `rank(I ⊕ L)` (`det`) | `2-EM` Whitening Ranks `(K^(0), K^(1), K^(2))` | Valid Keys / `(M, C)` | Classical OWF Security |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Unconstrained `(K1, K2)` | `512` b | — | — | `256 / 256 / 256` (unlinked) | `2^256` (**broken**) | `2^0` (`1` evaluation!) |
| Identical `K2 = K1` (`L = I`) | `256` b | `256 / 256` (`1`) | `0 / 256` (`0`, **fails**) | `256 / 256 / 0` (**broken**) | `~1` | `2^128` (shift attack) |
| Zero mask `MulOrtho256((0, 0), K)` | `256` b | `0 / 256` (`0`, **fails**) | `256 / 256` (`1`) | `256 / 0 / 256` (**broken**) | `~1` | `2^128` (unwhitened) |
| **`OrthoSigma256(K) = (K_R, K_L ⊕ K_R)`** | `256` b | **`256 / 256` (`1`)** | **`256 / 256` (`1`)** | **`256 / 256 / 256`** | `~1` | **`2^256`** (`2^128` quantum) |
| **`MulOrtho256(T, K)` (`T[0]\|=2, T[16]\|=2`)** | `256` b | **`256 / 256` (`1`)** | **`256 / 256` (`1`)** | **`256 / 256 / 256`** | `~1` | **`2^256`** (`2^128` quantum) |
| **`FAEST-Areion-128` (`K = k \|\| k, T * K`)** | `128` b | **`128 / 128` (`1`)** | **`128 / 128` (`1`)** | **`128 / 128 / 128`** | `~1` (`2^-128` coll.) | **`2^128`** (`2^64` quantum) |

---

### D. `SLH-DSA-Areion` Tweak-Cancellation Rank Audit and IPM Multi-Target Bounds

In `NIST FIPS 205` (`SLH-DSA`), the security reduction to single-function multi-target target-collision resistance (`SM-TCR`), preimage resistance (`SM-PRE`), and undetectability (`SM-UD`) over `T <= 2^64` addressed tweakable hash calls requires that an attacker who controls the message input `M1` cannot cancel differences in the public address tweak `ADRS` inside the underlying permutation query.

Check `tweak` (`py/slh_tweak_separation.py`, `results/tweak.txt`) and check `slh` (`go/slh_collision.go`, `results/slh.txt`) prove and empirically demonstrate why a naive feed-forward `TEM` mode fails catastrophically and how the three `areion-pq` tweakable hash profiles prevent tweak cancellation:

1. **Why Naive Feed-Forward `F_naive(K_pub, ADRS, M1) = TEMEncrypt256(K_pub, ADRS, M1) ⊕ M1` Fails (`Quotient Rank = 0 / 256`):**
   In `TEMEncrypt256(K_pub, ADRS, M1)`, the tweak `ADRS` is whitened into `W(ADRS) = P2(ADRS ⊕ K_pub2) ⊕ K_pub1`, and the ciphertext is `P1(M1 ⊕ W(ADRS)) ⊕ W(ADRS)`. Adding the feed-forward `⊕ M1` yields:
   `F_naive(K_pub, ADRS, M1) = P1(M1 ⊕ W(ADRS)) ⊕ (M1 ⊕ W(ADRS)) = DM256(U)` where `U = M1 ⊕ W(ADRS)`.
   Because `K_pub = (K_pub1, K_pub2)` is derived deterministically from the public key `PK.seed`, any party can compute `W(ADRS)` for any address `ADRS`. Given a target `(ADRS, M1)` and any distinct address `ADRS' != ADRS`, setting `M1' = M1 ⊕ W(ADRS) ⊕ W(ADRS')` gives `U' = M1' ⊕ W(ADRS') = M1 ⊕ W(ADRS) = U`, producing a **deterministic `O(1)` 1-query multi-target collision `F_naive(K_pub, ADRS', M1') == F_naive(K_pub, ADRS, M1)`** (`10,000 / 10,000` empirical collisions in `go/slh_collision.go`).
2. **Profile I — `SLHF256` (`DM512-Clamped`, `Quotient Rank = 256 / 256`):**
   `SLHF256(K_pub, ADRS, M1) = DM512((ADRS ⊕ K_pub1) || (M1 ⊕ K_pub2))` places the 256-bit whitened address `ADRS ⊕ K_pub1` in bytes `0..31` and the 256-bit whitened message `M1 ⊕ K_pub2` in bytes `32..63` of the 512-bit permutation `P1_512`. Varying `M1` leaves the 256-bit capacity lane `B[0:32]` invariant (`quotient rank = 256 / 256`, `0 / 10,000` empirical shift collisions).
3. **Category 1 — `SLHF128` and `SLHH128` (`Disjoint-Domain DM512`, `Quotient Rank = 384 / 384` and `256 / 256`):**
   `SLHF128` packs `(PK.seed[0:16] || ADRS[0:32] || M1[0:16]) ⊕ K_pub` into `DM512`, clamping `384` bits (`128` bits of `PK.seed` + `256` bits of `ADRS`) outside `Span(M1)`. `SLHH128` packs `(PK.seed[0:16] || ADRS_compact(ADRS)[0:16] || M1[0:16] || M2[0:16]) ⊕ K_pub`, where `ADRS_compact` extracts all `128` active `FIPS 205` address bits (`layer` 8b, `tree` 64b, `type` 8b, `keypair` 16b, `chain/height` 8b, `hash/index` 24b) with `GF(2)` rank `128 / 128` (`quotient rank = 256 / 256` for `PK.seed || ADRS_compact`).
4. **Profile II — `SLHFTEM256` (`TEM-MiddleTweak`, `Quotient Rank = 256 / 256`):**
   `SLHFTEM256(K_pub, ADRS, M1) = TEMEncrypt256(K_pub, M1, ADRS) ⊕ M1 = P1(ADRS ⊕ W(M1)) ⊕ W(M1) ⊕ M1`, where `W(M1) = P2(M1 ⊕ K_pub2) ⊕ K_pub1`. Because `M1` passes through the nonlinear permutation `P2` before XORing with `ADRS` inside `P1` while the outer feed-forward XORs `W(M1) ⊕ M1`, any message change `M1 -> M1'` shifts the outer feed-forward by `(W(M1') ⊕ M1') ⊕ (W(M1) ⊕ M1) != 0` even if `ADRS` were varied (`quotient rank = 256 / 256`, `0 / 10,000` empirical shift collisions).

| Construction | State `b` | Clamped Tweak Quotient Rank | Shift-Collision Rate (`10,000` trials) | Classical IPM Bound | Quantum / Grover Bound |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Naive `TEMEncrypt256(K_pub, ADRS, M1) ⊕ M1` | `256` b | `0 / 256` (**broken**) | `10,000 / 10,000` (`100.0%`) | `2^0` (`1` query) | `2^0` (`1` query) |
| `SLHF128` (`Disjoint PK.seed \|\| ADRS`) | `512` b | `384 / 384` | `0 / 10,000` (`0.0%`) | `2^128.0` | `2^64.0` (NIST Cat 1) |
| `SLHH128` (`PK.seed \|\| ADRS_compact`) | `512` b | `256 / 256` (`128/128` ADRS) | `0 / 10,000` (`0.0%`) | `2^128.0` | `2^64.0` (NIST Cat 1) |
| `SLHF256` (Profile I `DM512-Clamped`) | `512` b | `256 / 256` | `0 / 10,000` (`0.0%`) | `2^255.0` | `2^128.0` (NIST Cat 5) |
| `SLHFTEM256` (Profile II `TEM-MiddleTweak`) | `256` b | `256 / 256` | `0 / 10,000` (`0.0%`) | `2^254.0` | `2^127.0` (NIST Cat 5) |
| `SLHH256` (2-Step Cascaded `DM512`) | `512` b | `256 / 256` | `0 / 10,000` (`0.0%`) | `2^255.0` | `2^128.0` (NIST Cat 5) |
| `SLHPRF128` / `SLHPRF256` (`SoEM256` BBB PRF) | `256` b | `512` b secret key | — | `2^170.7` (`2n/3`) | `2^85.3` |

---

### E. Post-Quantum Parameter, Witness, and Signature Size Comparison

Check `bounds` (`py/pq_bounds_comparison.py`, `results/bounds.txt`) tabulates the exact witness dimensions, S-box counts, GGM tree openings, and signature byte layouts across all `areion-pq` schemes:

#### 1. Track 1 (`FAEST-Areion` vs `FAEST-256` and `FAEST-EM-256`)

| Variant | `lambda` | `k_bytes` | `w_bytes` | `L_bytes` (`L_bits`) | S-Boxes (Free) | `tau` | `PK` (B) | `SK` (B) | `Sig` (B) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`FAEST-Areion-128s`** | `16 B` | `16 B` | `288 B` | `304 B` (`2,432` b) | `320` (`32` free) | `13` | `48 B` | `64 B` | `6,448 B` |
| **`FAEST-Areion-128f`** | `16 B` | `16 B` | `288 B` | `304 B` (`2,432` b) | `320` (`32` free) | `16` | `48 B` | `64 B` | `7,456 B` |
| **`FAEST-Areion-256s`** | `32 B` | `32 B` | `288 B` | `320 B` (`2,560` b) | `320` (`32` free) | `26` | `64 B` | `96 B` | `18,208 B` |
| **`FAEST-Areion-256f`** | `32 B` | `32 B` | `288 B` | `320 B` (`2,560` b) | `320` (`32` free) | `32` | `64 B` | `96 B` | `20,512 B` |
| **`FAEST-Areion-EM2-256s`** | `32 B` | `32 B` | `576 B` | `608 B` (`4,864` b) | `640` (`64` free) | `26` | `64 B` | `96 B` | `25,696 B` |
| **`FAEST-Areion-EM2-256f`** | `32 B` | `32 B` | `576 B` | `608 B` (`4,864` b) | `640` (`64` free) | `32` | `64 B` | `96 B` | `30,368 B` |
| `FAEST-EM-256` (`Rijndael-256` 14r) | `32 B` | `32 B` | `448 B` | `480 B` (`3,840` b) | `448` (`0` free) | `32` | `64 B` | `96 B` | `~25,100 B` |
| `FAEST-256` (`2x AES-256 + KeySched`) | `32 B` | `32 B` | `480 B` | `512 B` (`4,096` b) | `500` (`0` free) | `32` | `64 B` | `96 B` | `~26,700 B` |

#### 2. Track 2 (`SLH-DSA-Areion` `NIST FIPS 205` Parameter Sets)

| Parameter Set | `n` | `h` | `d` | `h'` | `a` | `k` | `len` | `PK` (B) | `SK` (B) | `Sig` (B) | Sign Hash Calls | Verify Hash Calls (max) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`SLH-DSA-Areion-128f`** | `16` | `66` | `22` | `3` | `6` | `33` | `35` | `32 B` | `64 B` | `17,088 B` | `96,745` | `11,849` |
| **`SLH-DSA-Areion-128s`** | `16` | `63` | `7` | `9` | `12` | `14` | `35` | `32 B` | `64 B` | `7,856 B` | `1,999,851` | `3,922` |
| **`SLH-DSA-Areion-256f`** | `32` | `68` | `17` | `4` | `9` | `35` | `67` | `64 B` | `128 B` | `49,856 B` | `309,420` | `17,505` |
| **`SLH-DSA-Areion-256s`** | `32` | `64` | `8` | `8` | `14` | `22` | `67` | `64 B` | `128 B` | `29,792 B` | `2,781,154` | `8,436` |
| **`SLH-DSA-Areion-TEM-256f`** | `32` | `68` | `17` | `4` | `9` | `35` | `67` | `64 B` | `128 B` | `49,856 B` | `309,420` | `17,505` |

#### 3. Track 3 (`Areion-TEM2-SIV` vs Classical AEAD Constructions)

| AEAD Construction | Block `b` | Key `k` | Nonce | Tag | Classical Bound | Quantum Bound | Nonce-Misuse Behavior |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `AES-256-GCM` (`SP 800-38D`) | `128` b | `256` b | `96` b | `128` b | `2^64.0` | `2^32.0` | Catastrophic (`GHASH` key recovery + stream reuse) |
| `AES-256-GCM-SIV` (`RFC 8452`) | `128` b | `256` b | `96` b | `128` b | `2^64.0` | `2^32.0` | 128-bit MRAE (capped by 128-bit block birthday bound) |
| **`Areion-TEM2-SIV`** | **`512` b** | **`1024` b** | **`256` b** | **`256` b** | **`2^341.3` (`2n/3`)** | **`2^170.7`** | **Full 256-bit SIV + 512-bit wide-block TPRP MRAE** |

---

### F. Empirical Go & C Verification (`witness`, `slh`, `vole`, `integral`)

1. **Witness Completeness & Single-Bit Corruption Soundness (`go/witness_check.go`, `results/witness.txt`):**
   - `100,000 / 100,000` random `(M, K1, K2)` tuples pass `ExtractWitness256` (`P1`), `ExtractWitness256P2` (`P2`), and `ExtractWitnessEM2_256` (`EM2`) degree-2 `GF(2^8)` verification and match `areion.EMEncrypt256`, `areion.Permute256P2`, and `areion.EM2Encrypt256` bit-for-bit.
   - Across `20` random instances, flipping each of the `2,304` committed witness bits (`46,080` single-bit corruptions total, including all `20 x 256 = 5,120` Round 8->9 boundary bits `w[256:288]`), each of the `256` output bits of `C` (`5,120` flips testing the uncommitted Round 9 S-boxes), and each of the `256` secret key bits of `K1` (`5,120` flips), plus `100,000` random multi-bit witness corruptions, produces **`100.0%` rejection (`0` soundness false positives)**.
2. **Bitwise Avalanche and Byte Uniformity (`go/slh_collision.go`, `results/slh.txt`):**
   - Over `4,096` samples per primitive (`1,024` in `--quick`), single-bit flips in `ADRS` and `M1`/`M2` achieve strict bitwise avalanche across all 6 `SLH-DSA-Areion` primitives (`SLHF128`, `SLHF256`, `SLHFTEM256`, `SLHH128`, `SLHH256`, `SLHPRF256`) and `TEM2-SIV` (`meanHW = 0.49997 .. 0.50003`, `minHW >= 0.4979`, `maxHW <= 0.5023`, `maxBias <= 0.0415`, and per-byte uniformity `maxChi2(255) <= 318.2`).
3. **`QuickSilver` `GF(2^128)` VOLE & `TEM2-SIV` Forgery Rejection (`go/vole_check.go`, `results/vole.txt`):**
   - `10,000 / 10,000` random `GF(2^128)` triples pass commutativity, associativity, distributivity, and Frobenius linearity `(a ⊕ b)^2 == a^2 ⊕ b^2`, and `10,000 / 10,000` distinct key pairs satisfy `L(K1 ⊕ K2) != 0` and `(I ⊕ L)(K1 ⊕ K2) != 0`.
   - `200 / 200` 32-S-box `QuickSilver` VOLE aggregations pass `W_verif == W_poly` on valid witnesses and `200 / 200` reject 1-bit S-box output corruptions (`100.0%`).
   - `TEM2-SIV` rejects `1,600 / 1,600` 1-bit ciphertext forgeries (wiping `1,600 / 1,600` output buffers to all-zero) and `256 / 256` 1-bit tag forgeries (`100.0%`).
4. **Hardware `AES-NI` + `PCLMULQDQ` `Lambda`-Set Integral Check (`c/pq_integral.c`, `results/integral.txt`):**
   - Over `Lambda`-sets of Order 1 (`256` texts) and Order 2 (`65,536` texts) on the active `FIPS 205` diagonal of `ADRS` (`bytes 16..31`), `SLHF128` (`16 B`) and `SLHF256` (`32 B`) balance `16 / 16` and `32 / 32` output bytes for `r = 1..4`, `8 / 16` and `12..16 / 32` at `r = 5` (matching the 5-round integral bound of `Areion-512`), and `0 / 16` and `0 / 32` from `r = 6` through full `r = 15`.
   - `SLHFTEM256` (`32 B`) balances `32 / 32` output bytes at `r = 1..2`, `16 / 32` at `r = 3` (matching the 3-round integral bound of `Areion-256`), and `0 / 32` from `r = 4` through full `r = 10`.
   - `1,000,000 / 1,000,000` hardware `PCLMULQDQ` `QuickSilver` VOLE AND-gate evaluations satisfy `B_V == A0 ⊕ (A1 * Delta)` with `0` errors.

---

## Reproducing

### Dependencies

Go at the version in `go.mod`, Python 3.9 or later (standard library only), and for `integral` a C compiler, `make`, and an x86-64 CPU with `AES-NI` and `PCLMULQDQ`.

### Running

```
python3 analysis/run.py list                        # list all checks with expected run times
python3 analysis/run.py all --quick                 # run every check with reduced sample sizes (~20 s)
python3 analysis/run.py all --record                # run full suite and write analysis/results/*.txt (~35 s)
python3 analysis/run.py <check> [--quick] [--record]
python3 analysis/run.py clean                       # remove analysis/build
```

Run from the module root (`/home/andrew/go/src/areion-pq`). The Go binary (`analysis/build/analysis`) and C binary (`analysis/build/pq_integral`) are built automatically into `analysis/build/`, and `--record` writes deterministic logs to `analysis/results/<check>.txt`.

| Directory | Contents |
|---|---|
| `py/` | Symbolic `GF(2)` Jacobian rank verifier (`round9_witness_rank.py`), exhaustive `65,536`-pair `QuickSilver` S-box verifier (`quicksilver_sbox_soundness.py`), `GF(2)^256` orthomorphism rank verifier (`orthomorphism_bijectivity.py`), `SLH-DSA` tweak-cancellation rank & IPM bound calculator (`slh_tweak_separation.py`), and post-quantum parameter/bound tabulator (`pq_bounds_comparison.py`) |
| `go/` | Empirical `100,000`-trial witness & single-bit soundness verifier (`witness_check.go`), `SLH-DSA-Areion` avalanche, `chi^2(255)` & shift-collision verifier (`slh_collision.go`), and `GF(2^128)` `QuickSilver` VOLE & `TEM2-SIV` verifier (`vole_check.go`) |
| `c/` | `AES-NI` + `PCLMULQDQ` `Lambda`-set zero-sum integral and `1,000,000`-gate `QuickSilver` VOLE verifier (`pq_integral.c`, `Makefile`) |
| `results/` | Deterministic reference outputs of all checks (`rank.txt`, `sbox_qs.txt`, `ortho.txt`, `tweak.txt`, `bounds.txt`, `witness.txt`, `slh.txt`, `vole.txt`, `integral.txt`) |
