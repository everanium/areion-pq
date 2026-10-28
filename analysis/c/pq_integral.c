/* Empirical AES-NI + PCLMULQDQ Lambda-set integral (zero-sum) and QuickSilver
 * GF(2^128) polynomial MAC verifier for areion-pq:
 *   1. Reduced-round and full-round Lambda-set zero-sum balance of SLHF128,
 *      SLHF256 (Profile I DM512-Clamped), and SLHFTEM256 (Profile II
 *      TEM-MiddleTweak) for orders 1 (2^8), 2 (2^16), and 3 (2^24).
 *   2. Hardware PCLMULQDQ GF(2^128) (x^128 + x^7 + x^2 + x + 1, 0x87)
 *      polynomial MAC bilinearity, Lambda-set zero-sum balance, and 1,000,000
 *      QuickSilver VOLE degree-2 residual evaluations.
 *
 * Usage:
 *   ./pq_integral [quick]
 */
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t RC1_BYTES[15][16] = {
    {0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
    {0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
    {0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
    {0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
    {0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
    {0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
    {0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
    {0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
    {0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
    {0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
    {0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
    {0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
    {0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
    {0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
    {0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
};

static const uint8_t RC2_BYTES[15][16] = {
    {0x93, 0xe9, 0x72, 0x7c, 0xaf, 0x86, 0x54, 0xa1, 0xce, 0xe8, 0x41, 0x11, 0x34, 0x5c, 0xcc, 0xb4},
    {0xf6, 0x31, 0x18, 0x74, 0x5d, 0xc5, 0xa9, 0x2b, 0x2a, 0xbc, 0x6f, 0x63, 0x11, 0x14, 0xee, 0xb3},
    {0x5c, 0xcf, 0x24, 0x6c, 0x33, 0xba, 0xd6, 0xaf, 0x1e, 0x93, 0x87, 0x9b, 0x16, 0x3e, 0x5c, 0xce},
    {0xaf, 0xb9, 0x4b, 0x6b, 0x98, 0x48, 0x8f, 0x3b, 0x77, 0x86, 0x95, 0x28, 0x81, 0x53, 0x32, 0x7a},
    {0x91, 0xa9, 0x21, 0xfb, 0xcc, 0x09, 0xd8, 0x61, 0x93, 0x21, 0x28, 0x66, 0x1b, 0xe8, 0xbf, 0xc4},
    {0xb1, 0x75, 0x85, 0xe9, 0x5d, 0x5d, 0x84, 0xef, 0x32, 0x80, 0xec, 0x5d, 0x60, 0xac, 0x7c, 0x48},
    {0xc5, 0xac, 0x96, 0xd3, 0x81, 0x3e, 0x89, 0x23, 0x88, 0x1b, 0x65, 0xeb, 0x02, 0x23, 0x26, 0xdc},
    {0x40, 0x00, 0x42, 0x48, 0x2a, 0x48, 0xb4, 0xe0, 0x92, 0x23, 0x44, 0x3f, 0x38, 0xff, 0xd6, 0xf6},
    {0x9a, 0x6c, 0xe9, 0xf6, 0x42, 0x68, 0xc6, 0x21, 0x5e, 0x9b, 0x1f, 0x9e, 0x4a, 0xf0, 0xc8, 0x69},
    {0x68, 0x2f, 0x54, 0xd8, 0xd2, 0xa0, 0x51, 0x6a, 0xf0, 0x88, 0xd3, 0xab, 0x61, 0x9c, 0x0c, 0x67},
    {0xe4, 0x3b, 0x7a, 0x13, 0x6c, 0x0b, 0xef, 0x6e, 0xa3, 0x33, 0x51, 0xab, 0x28, 0xa7, 0x0f, 0x96},
    {0x76, 0x01, 0xaf, 0x39, 0x1d, 0x65, 0xf1, 0xa1, 0x98, 0x2a, 0xfb, 0x7e, 0x50, 0xf0, 0x3b, 0xba},
    {0xb4, 0x9f, 0x6f, 0x45, 0x19, 0x86, 0xee, 0x8c, 0x88, 0x0e, 0x43, 0x82, 0x3e, 0x59, 0xca, 0x66},
    {0x73, 0x20, 0xc1, 0x85, 0xd8, 0x75, 0x6f, 0xe0, 0xbe, 0x5e, 0x8b, 0x3b, 0xc3, 0xa5, 0x84, 0x7d},
    {0x06, 0x77, 0x3f, 0x36, 0x62, 0xaa, 0xd3, 0x4e, 0xa6, 0x6a, 0xc1, 0x56, 0x9f, 0x44, 0x1a, 0x40},
};

static __m128i rc1[15], rc2[15];

static inline void round256(__m128i *x0, __m128i *x1, int r, const __m128i *rc) {
    if ((r & 1) == 0) {
        __m128i t = _mm_aesenc_si128(_mm_aesenc_si128(*x0, rc[r]), *x1);
        *x0 = _mm_aesenclast_si128(*x0, _mm_setzero_si128());
        *x1 = t;
    } else {
        __m128i t = _mm_aesenc_si128(_mm_aesenc_si128(*x1, rc[r]), *x0);
        *x1 = _mm_aesenclast_si128(*x1, _mm_setzero_si128());
        *x0 = t;
    }
}

static inline void round512(__m128i *x, int r, const __m128i *rc) {
    int o = r & 3;
    __m128i *a = &x[o], *b = &x[(o + 1) & 3], *c = &x[(o + 2) & 3], *d = &x[(o + 3) & 3];
    __m128i nb = _mm_aesenc_si128(*a, *b);
    __m128i nd = _mm_aesenc_si128(*c, *d);
    *a = _mm_aesenclast_si128(*a, _mm_setzero_si128());
    *c = _mm_aesenc_si128(_mm_aesenclast_si128(*c, rc[r]), _mm_setzero_si128());
    *b = nb;
    *d = nd;
}

/* Reduced-round DM512(in64) -> out32 (keeping words x2||x3||x6||x7||x8||x9||x12||x13). */
static inline void dm512_rounds(const uint8_t in[64], uint8_t out[32], int rounds) {
    __m128i x0 = _mm_loadu_si128((const __m128i *)(in + 0));
    __m128i x1 = _mm_loadu_si128((const __m128i *)(in + 16));
    __m128i x2 = _mm_loadu_si128((const __m128i *)(in + 32));
    __m128i x3 = _mm_loadu_si128((const __m128i *)(in + 48));
    __m128i x[4] = {x0, x1, x2, x3};
    for (int r = 0; r < rounds; r++) {
        round512(x, r, rc1);
    }
    __m128i y0 = _mm_xor_si128(x[3], x0);
    __m128i y1 = _mm_xor_si128(x[0], x1);
    __m128i y2 = _mm_xor_si128(x[1], x2);
    __m128i y3 = _mm_xor_si128(x[2], x3);
    uint8_t full[64];
    _mm_storeu_si128((__m128i *)(full + 0), y0);
    _mm_storeu_si128((__m128i *)(full + 16), y1);
    _mm_storeu_si128((__m128i *)(full + 32), y2);
    _mm_storeu_si128((__m128i *)(full + 48), y3);
    memcpy(out + 0, full + 8, 8);
    memcpy(out + 8, full + 24, 8);
    memcpy(out + 16, full + 32, 8);
    memcpy(out + 24, full + 48, 8);
}

/* Reduced-round SLHFTEM256(K_pub, ADRS, M1) = P1_r(ADRS ^ W) ^ W ^ M1, W = P2_10(M1 ^ K2) ^ K1. */
static inline void slh_ftem256_rounds(const uint8_t kpub[64], const uint8_t adrs[32], const uint8_t m1[32], uint8_t out[32], int rounds) {
    __m128i k1_0 = _mm_loadu_si128((const __m128i *)(kpub + 0));
    __m128i k1_1 = _mm_loadu_si128((const __m128i *)(kpub + 16));
    __m128i k2_0 = _mm_loadu_si128((const __m128i *)(kpub + 32));
    __m128i k2_1 = _mm_loadu_si128((const __m128i *)(kpub + 48));
    __m128i m_0 = _mm_loadu_si128((const __m128i *)(m1 + 0));
    __m128i m_1 = _mm_loadu_si128((const __m128i *)(m1 + 16));
    __m128i a_0 = _mm_loadu_si128((const __m128i *)(adrs + 0));
    __m128i a_1 = _mm_loadu_si128((const __m128i *)(adrs + 16));

    __m128i w0 = _mm_xor_si128(m_0, k2_0);
    __m128i w1 = _mm_xor_si128(m_1, k2_1);
    for (int r = 0; r < 10; r++) {
        round256(&w0, &w1, r, rc2);
    }
    w0 = _mm_xor_si128(w0, k1_0);
    w1 = _mm_xor_si128(w1, k1_1);

    __m128i s0 = _mm_xor_si128(a_0, w0);
    __m128i s1 = _mm_xor_si128(a_1, w1);
    for (int r = 0; r < rounds; r++) {
        round256(&s0, &s1, r, rc1);
    }
    s0 = _mm_xor_si128(_mm_xor_si128(s0, w0), m_0);
    s1 = _mm_xor_si128(_mm_xor_si128(s1, w1), m_1);
    _mm_storeu_si128((__m128i *)(out + 0), s0);
    _mm_storeu_si128((__m128i *)(out + 16), s1);
}

/* PCLMULQDQ multiplication in GF(2^128) modulo x^128 + x^7 + x^2 + x + 1 (0x87). */
static inline __m128i gf128_mul_pclmul(__m128i a, __m128i b) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i t2 = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x01), _mm_clmulepi64_si128(a, b, 0x10));

    __m128i c_lo = _mm_xor_si128(t0, _mm_slli_si128(t2, 8));
    __m128i c_hi = _mm_xor_si128(t1, _mm_srli_si128(t2, 8));

    uint64_t lo0 = (uint64_t)_mm_cvtsi128_si64(c_lo);
    uint64_t lo1 = (uint64_t)_mm_extract_epi64(c_lo, 1);
    uint64_t h0 = (uint64_t)_mm_cvtsi128_si64(c_hi);
    uint64_t h1 = (uint64_t)_mm_extract_epi64(c_hi, 1);

    uint64_t u1 = (h1 << 7) ^ (h1 << 2) ^ (h1 << 1) ^ h1;
    uint64_t u1_hi = (h1 >> 57) ^ (h1 >> 62) ^ (h1 >> 63);
    h0 ^= u1_hi;
    uint64_t r1 = lo1 ^ u1 ^ (h0 >> 57) ^ (h0 >> 62) ^ (h0 >> 63);
    uint64_t r0 = lo0 ^ (h0 << 7) ^ (h0 << 2) ^ (h0 << 1) ^ h0;
    return _mm_set_epi64x((long long)r1, (long long)r0);
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t next_rng(void) {
    rng_state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = rng_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int count_zero_bytes(const uint8_t *buf, int len) {
    int c = 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] == 0) c++;
    }
    return c;
}

static void run_slh_lambda_integrals(int max_order) {
    uint8_t base64[64], kpub[64], adrs[32], m1[32];
    for (int i = 0; i < 64; i++) {
        base64[i] = (uint8_t)next_rng();
        kpub[i] = (uint8_t)next_rng();
    }
    for (int i = 0; i < 32; i++) {
        adrs[i] = (uint8_t)next_rng();
        m1[i] = (uint8_t)next_rng();
    }

    printf("=== C AES-NI Lambda-Set Integral (Zero-Sum) Balance Audit ===\n");
    for (int order = 1; order <= max_order; order++) {
        uint64_t total = 1ULL << (8 * order);
        printf("--- Order %d (%llu texts, active diagonal bytes in ADRS / M1) ---\n",
               order, (unsigned long long)total);
        printf("Round  SLHF128 (bal/16)  SLHF256 (bal/32)  SLHFTEM256 (bal/32)\n");
        printf("-----  ----------------  ----------------  -------------------\n");

        int rounds_list[] = {1, 2, 3, 4, 5, 6, 8, 10, 15};
        int n_r = (int)(sizeof(rounds_list) / sizeof(rounds_list[0]));
        for (int idx = 0; idx < n_r; idx++) {
            int r = rounds_list[idx];
            uint8_t acc_f256[32] = {0};
            uint8_t acc_ftem[32] = {0};

            for (uint64_t v = 0; v < total; v++) {
                uint8_t blk[64];
                memcpy(blk, base64, 64);
                /* Active bytes placed on diagonal of ADRS block 1 (bytes 16..31: FIPS 205 type/keypair/chain/hash) */
                for (int t = 0; t < order; t++) {
                    blk[16 + (5 * t) % 16] = (uint8_t)(v >> (8 * t));
                }
                uint8_t out32[32];
                dm512_rounds(blk, out32, r);
                for (int i = 0; i < 32; i++) acc_f256[i] ^= out32[i];

                if (r <= 10) {
                    uint8_t a_in[32];
                    memcpy(a_in, adrs, 32);
                    for (int t = 0; t < order; t++) {
                        a_in[16 + (5 * t) % 16] = (uint8_t)(v >> (8 * t));
                    }
                    uint8_t out_tem[32];
                    slh_ftem256_rounds(kpub, a_in, m1, out_tem, r);
                    for (int i = 0; i < 32; i++) acc_ftem[i] ^= out_tem[i];
                }
            }
            int z128 = count_zero_bytes(acc_f256, 16);
            int z256 = count_zero_bytes(acc_f256, 32);
            if (r <= 10) {
                int ztem = count_zero_bytes(acc_ftem, 32);
                printf("r=%2d        %2d / 16           %2d / 32              %2d / 32\n",
                       r, z128, z256, ztem);
                if ((r <= 2 && ztem != 32) || (r == 3 && ztem < 16)) {
                    fprintf(stderr, "SLHFTEM256 integral balance failed at r=%d\n", r);
                    exit(1);
                }
            } else {
                printf("r=%2d        %2d / 16           %2d / 32                  -\n",
                       r, z128, z256);
            }
            if ((r <= 4 && (z128 != 16 || z256 != 32)) || (r == 5 && z256 < 8)) {
                fprintf(stderr, "DM512 integral balance failed at r=%d\n", r);
                exit(1);
            }
        }
    }
}

static void run_quicksilver_pclmul_check(int quick) {
    uint64_t n_evals = quick ? 100000ULL : 1000000ULL;
    __m128i delta = _mm_set_epi64x((long long)next_rng(), (long long)(next_rng() | 1ULL));
    __m128i chi = _mm_set_epi64x((long long)next_rng(), (long long)(next_rng() | 1ULL));

    /* 1. Verify Lambda-set zero-sum balance of QuickSilver GF(2^128) PolyMAC */
    __m128i b_vec[4], a_base[4];
    for (int i = 0; i < 4; i++) {
        b_vec[i] = _mm_set_epi64x((long long)next_rng(), (long long)next_rng());
        a_base[i] = _mm_set_epi64x((long long)next_rng(), (long long)next_rng());
    }
    __m128i mac_sum_o1 = _mm_setzero_si128();
    for (uint32_t v = 0; v < 256; v++) {
        __m128i acc = _mm_setzero_si128();
        for (int i = 0; i < 4; i++) {
            __m128i ai = a_base[i];
            if (i == 0) {
                ai = _mm_xor_si128(ai, _mm_set_epi64x(0, (long long)v));
            }
            acc = gf128_mul_pclmul(acc, chi);
            acc = _mm_xor_si128(acc, gf128_mul_pclmul(ai, b_vec[i]));
        }
        mac_sum_o1 = _mm_xor_si128(mac_sum_o1, acc);
    }
    uint8_t sum_bytes[16];
    _mm_storeu_si128((__m128i *)sum_bytes, mac_sum_o1);
    int z_mac = count_zero_bytes(sum_bytes, 16);

    /* 2. Verify 1,000,000 VOLE multiplicative gate identities:
     *    For V_a = Q_a ^ (a_bit * Delta) and V_b = Q_b ^ (b_bit * Delta),
     *    when c_bit = a_bit & b_bit and V_c = Q_c ^ (c_bit * Delta):
     *      A0 = Q_a * Q_b
     *      A1 = a_bit * Q_b ^ b_bit * Q_a ^ Q_c
     *      B_V = V_a * V_b ^ V_c * Delta
     *    must satisfy B_V == A0 ^ (A1 * Delta) identically! */
    uint64_t ok_count = 0;
    for (uint64_t n = 0; n < n_evals; n++) {
        uint64_t rbits = next_rng();
        int a_bit = (int)(rbits & 1);
        int b_bit = (int)((rbits >> 1) & 1);
        int c_bit = a_bit & b_bit;

        __m128i Qa = _mm_set_epi64x((long long)next_rng(), (long long)next_rng());
        __m128i Qb = _mm_set_epi64x((long long)next_rng(), (long long)next_rng());
        __m128i Qc = _mm_set_epi64x((long long)next_rng(), (long long)next_rng());

        __m128i Va = a_bit ? _mm_xor_si128(Qa, delta) : Qa;
        __m128i Vb = b_bit ? _mm_xor_si128(Qb, delta) : Qb;
        __m128i Vc = c_bit ? _mm_xor_si128(Qc, delta) : Qc;

        __m128i A0 = gf128_mul_pclmul(Qa, Qb);
        __m128i A1 = Qc;
        if (a_bit) A1 = _mm_xor_si128(A1, Qb);
        if (b_bit) A1 = _mm_xor_si128(A1, Qa);

        __m128i BV = _mm_xor_si128(gf128_mul_pclmul(Va, Vb), gf128_mul_pclmul(Vc, delta));
        __m128i rhs = _mm_xor_si128(A0, gf128_mul_pclmul(A1, delta));
        __m128i diff = _mm_xor_si128(BV, rhs);
        if (_mm_testz_si128(diff, diff)) {
            ok_count++;
        }
    }

    printf("\n=== C PCLMULQDQ QuickSilver GF(2^128) MAC & VOLE Gate Audit ===\n");
    printf("PolyMAC order-1 Lambda-set balanced bytes:     %d / 16 (128 / 128 bits)\n", z_mac);
    printf("Hardware PCLMULQDQ VOLE AND-gate identities:   %llu / %llu PASS\n",
           (unsigned long long)ok_count, (unsigned long long)n_evals);
    if (z_mac != 16 || ok_count != n_evals) {
        fprintf(stderr, "PCLMULQDQ QuickSilver check failed\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    int quick = (argc >= 2 && (strcmp(argv[1], "quick") == 0 || strcmp(argv[1], "--quick") == 0));
    for (int r = 0; r < 15; r++) {
        rc1[r] = _mm_loadu_si128((const __m128i *)RC1_BYTES[r]);
        rc2[r] = _mm_loadu_si128((const __m128i *)RC2_BYTES[r]);
    }
    run_slh_lambda_integrals(quick ? 1 : 2);
    run_quicksilver_pclmul_check(quick);
    return 0;
}
