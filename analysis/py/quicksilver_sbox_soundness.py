#!/usr/bin/env python3
"""Exhaustive algebraic verification over all 256 x 256 = 65,536 byte pairs
(X, S) in GF(2^8) (z^8 + z^4 + z^3 + z + 1, 0x11B) of the QuickSilver degree-2
AES S-box constraint system:

    C1(X, S) = Sq(X) * Y ^ X == 0
    C2(X, S) = Sq(Y) * X ^ Y == 0    where Y = AffineInv(S ^ 0x63).

Verifies:
  1. Bit-level gate equations for Sq_GF256, Affine, AffineInv, and Mul_GF256
     match field arithmetic on all 256 bytes and all 65,536 byte pairs.
  2. 100% Completeness: all 256 / 256 valid S-box pairs (X, S = AES_Sbox(X))
     satisfy C1(X, S) == 0 and C2(X, S) == 0, including the zero-input pair
     (X = 0x00, S = 0x63 -> Y = 0x00).
  3. 100% Soundness: 0 / 65,280 invalid pairs (X, S != AES_Sbox(X)) satisfy
     both C1 == 0 and C2 == 0 (all 65,280 / 65,280 invalid pairs rejected).
  4. Single-Equation Spurious Solution Audit:
     - C1(X, S) = Sq(X)*Y ^ X == 0 alone has 1 spurious solution X = 0x00 for
       each S != 0x63 (Y != 0), totaling 255 false accepts (0x00, S != 0x63).
     - C2(X, S) = Sq(Y)*X ^ Y == 0 alone has 1 spurious solution S = 0x63
       (Y = 0) for each X != 0x00, totaling 255 false accepts (X != 0, 0x63).
     - Naive X * Y ^ 1 == 0 fails completeness on (X = 0x00, S = 0x63).
  5. QuickSilver VOLE Homomorphic Gate Identity over GF(2^128) (x^128 + x^7 +
     x^2 + x + 1, 0x87): B_V == A0 ^ (A1 * Delta) holds for 256 / 256 valid
     pairs and fails with B_V ^ A0 ^ (A1 * Delta) == C_bit * Delta^2 != 0 on
     invalid pairs.
"""

import random


# --- Polynomial arithmetic in GF(2^8) modulo z^8 + z^4 + z^3 + z + 1 (0x11B) ---

def gf256_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF
        b >>= 1
    return r


def gf256_sq(a: int) -> int:
    return gf256_mul(a, a)


def gf256_inv(x: int) -> int:
    if x == 0:
        return 0
    r, a, e = 1, x, 254
    while e:
        if e & 1:
            r = gf256_mul(r, a)
        a = gf256_mul(a, a)
        e >>= 1
    return r


def gf256_affine(x: int) -> int:
    r = 0x63
    for i in range(8):
        b = 0
        for k in (0, 4, 5, 6, 7):
            b ^= (x >> ((i + k) % 8)) & 1
        r ^= b << i
    return r


def gf256_affine_inv(s: int) -> int:
    u = s ^ 0x63
    r = 0
    for i in range(8):
        b = ((u >> ((i + 2) % 8)) & 1) ^ ((u >> ((i + 5) % 8)) & 1) ^ ((u >> ((i + 7) % 8)) & 1)
        r |= b << i
    return r


SBOX = [gf256_affine(gf256_inv(x)) for x in range(256)]


# --- Bit-level gate circuits from Specification Section 2.4 ---

def byte_to_bits(v: int) -> list[int]:
    return [(v >> i) & 1 for i in range(8)]


def bits_to_byte(bits: list[int]) -> int:
    return sum((bits[i] & 1) << i for i in range(8))


def gate_sq_gf256(x: list[int]) -> list[int]:
    """Bit-level linear squaring U = Sq_GF256(X) in GF(2^8) modulo 0x11B.
    Monomial squares:
      z^0  -> 0x01 (bit 0)
      z^2  -> 0x04 (bit 2)
      z^4  -> 0x10 (bit 4)
      z^6  -> 0x40 (bit 6)
      z^8  -> 0x1B (bits 0, 1, 3, 4)
      z^10 -> 0x6C (bits 2, 3, 5, 6)
      z^12 -> 0xAB (bits 0, 1, 3, 5, 7)
      z^14 -> 0x9A (bits 1, 3, 4, 7)
    """
    return [
        x[0] ^ x[4] ^ x[6],
        x[4] ^ x[6] ^ x[7],
        x[1] ^ x[5],
        x[4] ^ x[5] ^ x[6] ^ x[7],
        x[2] ^ x[4] ^ x[7],
        x[5] ^ x[6],
        x[3] ^ x[5],
        x[6] ^ x[7],
    ]


def gate_affine_inv(s: list[int]) -> list[int]:
    """Bit-level inverse affine map Y = AffineInv(S ^ 0x63)."""
    sp = [s[b] ^ ((0x63 >> b) & 1) for b in range(8)]
    return [sp[(b + 2) % 8] ^ sp[(b + 5) % 8] ^ sp[(b + 7) % 8] for b in range(8)]


def gate_mul_gf256(a: list[int], b: list[int]) -> list[int]:
    """Bit-level bilinear multiplication P = Mul_GF256(A, B) modulo 0x11B."""
    d = [0] * 15
    for i in range(8):
        for j in range(8):
            d[i + j] ^= a[i] & b[j]
    r6 = d[14]
    r5 = d[13]
    r4 = d[12]
    r3 = d[11]
    r2 = d[10] ^ r6
    r1 = d[9] ^ r5 ^ r6
    r0 = d[8] ^ r4 ^ r5
    return [
        d[0] ^ r0,
        d[1] ^ r1 ^ r0,
        d[2] ^ r2 ^ r1,
        d[3] ^ r3 ^ r2 ^ r0,
        d[4] ^ r4 ^ r3 ^ r1 ^ r0,
        d[5] ^ r5 ^ r4 ^ r2 ^ r1,
        d[6] ^ r6 ^ r5 ^ r3 ^ r2,
        d[7] ^ r6 ^ r4 ^ r3,
    ]


def gate_constraints_16(x_byte: int, s_byte: int) -> tuple[int, int]:
    """Evaluate C1 and C2 via bit-level gate equations."""
    x = byte_to_bits(x_byte)
    s = byte_to_bits(s_byte)
    u = gate_sq_gf256(x)
    y = gate_affine_inv(s)
    w = gate_sq_gf256(y)
    p1 = gate_mul_gf256(u, y)
    p2 = gate_mul_gf256(w, x)
    c1 = [p1[i] ^ x[i] for i in range(8)]
    c2 = [p2[i] ^ y[i] for i in range(8)]
    return bits_to_byte(c1), bits_to_byte(c2)


# --- GF(2^128) arithmetic modulo x^128 + x^7 + x^2 + x + 1 (0x87) ---

POLY_GF128 = (1 << 128) | 0x87


def gf128_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & (1 << 128):
            a ^= POLY_GF128
        b >>= 1
    return r


def verify_vole_quicksilver_gate() -> tuple[int, int]:
    """Verify Prover (A0, A1) vs Verifier B_V homomorphic identity over GF(2^128)."""
    rng = random.Random(0x511C4511)
    delta = rng.getrandbits(128) | 1
    delta_sq = gf128_mul(delta, delta)

    def lift_sq(wires):
        return gate_sq_gf256(wires)

    def reduce_deg14(d):
        r6 = d[14]
        r5 = d[13]
        r4 = d[12]
        r3 = d[11]
        r2 = d[10] ^ r6
        r1 = d[9] ^ r5 ^ r6
        r0 = d[8] ^ r4 ^ r5
        return [
            d[0] ^ r0,
            d[1] ^ r1 ^ r0,
            d[2] ^ r2 ^ r1,
            d[3] ^ r3 ^ r2 ^ r0,
            d[4] ^ r4 ^ r3 ^ r1 ^ r0,
            d[5] ^ r5 ^ r4 ^ r2 ^ r1,
            d[6] ^ r6 ^ r5 ^ r3 ^ r2,
            d[7] ^ r6 ^ r4 ^ r3,
        ]

    def eval_vole_pair(x_byte: int, s_byte: int) -> tuple[bool, bool]:
        x_val = byte_to_bits(x_byte)
        s_val = byte_to_bits(s_byte)
        x_Q = [rng.getrandbits(128) for _ in range(8)]
        s_Q = [rng.getrandbits(128) for _ in range(8)]
        x_V = [x_Q[i] ^ (delta if x_val[i] else 0) for i in range(8)]
        s_V = [s_Q[i] ^ (delta if s_val[i] else 0) for i in range(8)]

        u_val = gate_sq_gf256(x_val)
        u_Q = lift_sq(x_Q)
        u_V = lift_sq(x_V)

        y_val = gate_affine_inv(s_val)
        # Adding constant 1 in VOLE leaves Q unchanged and XORs Delta into V:
        sp_Q = s_Q[:]
        sp_V = [s_V[b] ^ (delta if ((0x63 >> b) & 1) else 0) for b in range(8)]
        y_Q = [sp_Q[(b + 2) % 8] ^ sp_Q[(b + 5) % 8] ^ sp_Q[(b + 7) % 8] for b in range(8)]
        y_V = [sp_V[(b + 2) % 8] ^ sp_V[(b + 5) % 8] ^ sp_V[(b + 7) % 8] for b in range(8)]

        w_val = gate_sq_gf256(y_val)
        w_Q = lift_sq(y_Q)
        w_V = lift_sq(y_V)

        # Bilinear product 1: U * Y ^ X
        d1_A0 = [0] * 15
        d1_A1 = [0] * 15
        d1_BV = [0] * 15
        # Bilinear product 2: W * X ^ Y
        d2_A0 = [0] * 15
        d2_A1 = [0] * 15
        d2_BV = [0] * 15

        for i in range(8):
            for j in range(8):
                d1_A0[i + j] ^= gf128_mul(u_Q[i], y_Q[j])
                d1_A1[i + j] ^= (y_Q[j] if u_val[i] else 0) ^ (u_Q[i] if y_val[j] else 0)
                d1_BV[i + j] ^= gf128_mul(u_V[i], y_V[j])

                d2_A0[i + j] ^= gf128_mul(w_Q[i], x_Q[j])
                d2_A1[i + j] ^= (x_Q[j] if w_val[i] else 0) ^ (w_Q[i] if x_val[j] else 0)
                d2_BV[i + j] ^= gf128_mul(w_V[i], x_V[j])

        p1_A0 = reduce_deg14(d1_A0)
        p1_A1 = [reduce_deg14(d1_A1)[i] ^ x_Q[i] for i in range(8)]
        p1_BV = [reduce_deg14(d1_BV)[i] ^ gf128_mul(x_V[i], delta) for i in range(8)]

        p2_A0 = reduce_deg14(d2_A0)
        p2_A1 = [reduce_deg14(d2_A1)[i] ^ y_Q[i] for i in range(8)]
        p2_BV = [reduce_deg14(d2_BV)[i] ^ gf128_mul(y_V[i], delta) for i in range(8)]

        c1_byte, c2_byte = gate_constraints_16(x_byte, s_byte)
        all_zero_diff = True
        exact_err_law = True
        for i in range(8):
            diff1 = p1_BV[i] ^ p1_A0[i] ^ gf128_mul(p1_A1[i], delta)
            diff2 = p2_BV[i] ^ p2_A0[i] ^ gf128_mul(p2_A1[i], delta)
            if diff1 != 0 or diff2 != 0:
                all_zero_diff = False
            exp1 = delta_sq if ((c1_byte >> i) & 1) else 0
            exp2 = delta_sq if ((c2_byte >> i) & 1) else 0
            if diff1 != exp1 or diff2 != exp2:
                exact_err_law = False
        return all_zero_diff, exact_err_law

    valid_ok = 0
    for x in range(256):
        z, law = eval_vole_pair(x, SBOX[x])
        if z and law:
            valid_ok += 1

    invalid_rejected = 0
    for _ in range(1000):
        x = rng.randrange(256)
        s = (SBOX[x] ^ rng.randrange(1, 256)) & 0xFF
        z, law = eval_vole_pair(x, s)
        if (not z) and law:
            invalid_rejected += 1

    return valid_ok, invalid_rejected


def main() -> None:
    # 1. Verify bit-level gates against GF(2^8) field arithmetic
    unary_ok = 0
    for x in range(256):
        xb = byte_to_bits(x)
        sq_gate = bits_to_byte(gate_sq_gf256(xb))
        ainv_gate = bits_to_byte(gate_affine_inv(xb))
        if (
            sq_gate == gf256_sq(x)
            and ainv_gate == gf256_affine_inv(x)
            and gf256_affine(gf256_affine_inv(x)) == x
            and gf256_affine_inv(gf256_affine(x)) == x
        ):
            unary_ok += 1

    mul_ok = 0
    for a in range(256):
        ab = byte_to_bits(a)
        for b in range(256):
            bb = byte_to_bits(b)
            if bits_to_byte(gate_mul_gf256(ab, bb)) == gf256_mul(a, b):
                mul_ok += 1

    # 2. Exhaustive 65,536-pair completeness and soundness audit
    valid_total = 0
    valid_pass_both = 0
    valid_pass_naive_xy1 = 0
    zero_pair_passes = False

    invalid_total = 0
    invalid_pass_both = 0
    invalid_pass_c1_only = 0
    invalid_pass_c2_only = 0
    c2_spurious_per_nonzero_x = 0
    c1_spurious_at_x0 = 0

    for x in range(256):
        for s in range(256):
            y = gf256_affine_inv(s)
            c1 = gf256_mul(gf256_sq(x), y) ^ x
            c2 = gf256_mul(gf256_sq(y), x) ^ y
            gc1, gc2 = gate_constraints_16(x, s)
            assert (c1, c2) == (gc1, gc2), "Bit-level gate mismatch with field equation"

            is_valid = (s == SBOX[x])
            if is_valid:
                valid_total += 1
                if c1 == 0 and c2 == 0:
                    valid_pass_both += 1
                    if x == 0x00 and s == 0x63:
                        zero_pair_passes = True
                if (gf256_mul(x, y) ^ 1) == 0:
                    valid_pass_naive_xy1 += 1
            else:
                invalid_total += 1
                if c1 == 0 and c2 == 0:
                    invalid_pass_both += 1
                if c1 == 0:
                    invalid_pass_c1_only += 1
                    if x == 0x00 and s != 0x63:
                        c1_spurious_at_x0 += 1
                if c2 == 0:
                    invalid_pass_c2_only += 1
                    if x != 0x00 and s == 0x63:
                        c2_spurious_per_nonzero_x += 1

    vole_valid_ok, vole_invalid_rej = verify_vole_quicksilver_gate()

    print("=== QuickSilver GF(2^8) Degree-2 S-Box Completeness & Soundness Audit ===")
    print(f"Bit-level unary gates (Sq, Affine, AffineInv): {unary_ok} / 256 exact")
    print(f"Bit-level bilinear multiplication (Mul_GF256): {mul_ok} / 65536 exact")
    print(f"Total (X, S) byte pairs evaluated:             {valid_total + invalid_total} (256 valid + 65280 invalid)")
    print(f"Valid S-box pairs passing (C1 == 0 & C2 == 0): {valid_pass_both} / {valid_total} (100% completeness)")
    print(f"Zero-input fixed point (X=0x00, S=0x63->Y=0):  {'PASS' if zero_pair_passes else 'FAIL'}")
    print(f"Invalid pairs passing (C1 == 0 & C2 == 0):     {invalid_pass_both} / {invalid_total} (100% soundness)")
    print(f"Invalid pairs rejected by (C1, C2) system:     {invalid_total - invalid_pass_both} / {invalid_total}")
    print("--- Single-Equation Spurious Solution Analysis ---")
    print(f"Naive X*Y ^ 1 == 0 completeness on valid pairs:{valid_pass_naive_xy1} / 256 (fails on X=0x00, S=0x63)")
    print(f"C1 alone (Sq(X)*Y ^ X == 0) false accepts:     {invalid_pass_c1_only} / 65280 (all {c1_spurious_at_x0} at X=0x00, S!=0x63)")
    print(f"C2 alone (Sq(Y)*X ^ Y == 0) false accepts:     {invalid_pass_c2_only} / 65280 (1 spurious S=0x63 per X!=0: {c2_spurious_per_nonzero_x} pairs)")
    print("--- QuickSilver GF(2^128) VOLE Homomorphic Gate Identity ---")
    print(f"Valid pairs satisfying B_V == A0 ^ A1*Delta:   {vole_valid_ok} / 256")
    print(f"Random invalid pairs rejected (err = C*Delta^2):{vole_invalid_rej} / 1000")

    assert unary_ok == 256
    assert mul_ok == 65536
    assert valid_pass_both == 256
    assert zero_pair_passes
    assert invalid_pass_both == 0
    assert invalid_pass_c1_only == 255 and c1_spurious_at_x0 == 255
    assert invalid_pass_c2_only == 255 and c2_spurious_per_nonzero_x == 255
    assert vole_valid_ok == 256
    assert vole_invalid_rej == 1000


if __name__ == "__main__":
    main()
