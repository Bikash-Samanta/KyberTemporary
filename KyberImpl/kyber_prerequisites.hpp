#pragma once
#include <span>
#include <cstdint>

#include "params.hpp"
#include "hash.hpp"
#include "kyber_ntt.hpp"


/**
 * @brief Returns the x-th polynomial from a polynomial vector.
 *
 * @param vector Polynomial vector containing KYBER_K polynomials.
 * @param x Polynomial index.
 * @return Mutable span containing KYBER_N coefficients of the x-th polynomial.
 */

inline std::span<int16_t, KYBER_N> range(std::span<int16_t, KYBER_K * KYBER_N> vector, size_t x) {
    return std::span<int16_t, KYBER_N>(vector.data() + (x) * KYBER_N, KYBER_N);
}

/**
 * @brief Returns the x-th polynomial-vector block from a larger vector.
 *
 * @param vector Vector containing KYBER_K polynomial-vector blocks.
 * @param x Block index.
 * @return Mutable span containing KYBER_K * KYBER_N coefficients of the x-th block.
 */

inline std::span<int16_t, KYBER_N * KYBER_K> range(std::span<int16_t, KYBER_K * KYBER_K * KYBER_N> vector, size_t x) {
    return std::span<int16_t, KYBER_N * KYBER_K>(vector.data() + (x) * KYBER_N * KYBER_K, KYBER_N * KYBER_K);
}

/**
 * @brief Returns the x-th polynomial from a polynomial vector as read-only data.
 *
 * @param vector Polynomial vector containing KYBER_K polynomials.
 * @param x Polynomial index.
 * @return Read-only span containing KYBER_N coefficients of the x-th polynomial.
 */
inline std::span<const int16_t, KYBER_N> crange(std::span<const int16_t, KYBER_K * KYBER_N> vector, size_t x) {
    return std::span<const int16_t, KYBER_N>(vector.data() + (x) * KYBER_N, KYBER_N);
}



inline void noise_polynomial_cbd2(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, 2 * KYBER_N / 4> buffer
) 
{
    uint32_t t, d;
    int16_t a, b;

    for (size_t i = 0; i < KYBER_N / 8; i++) {

        t =  static_cast<uint32_t>(buffer[4 * i])
          | (static_cast<uint32_t>(buffer[4 * i + 1]) << 8)
          | (static_cast<uint32_t>(buffer[4 * i + 2]) << 16)
          | (static_cast<uint32_t>(buffer[4 * i + 3]) << 24);

        d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (size_t j = 0; j < 8; j++) {
            a = (d >> (4 * j + 0)) & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            
            polynomial[8 * i + j] = a - b; 
        }
    }
}

inline void noise_polynomial_cbd3(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, 3 * KYBER_N / 4> buffer
) 
{
    uint32_t t, d;
    int16_t a, b;

    for (size_t i = 0; i < KYBER_N / 4; i++) {
        t =  static_cast<uint32_t>(buffer[3 * i])
          | (static_cast<uint32_t>(buffer[3 * i + 1]) << 8)
          | (static_cast<uint32_t>(buffer[3 * i + 2]) << 16);

        d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (size_t j = 0; j < 4; j++) {
            a = static_cast<int16_t>((d >> (6 * j + 0)) & 0x7);
            b = static_cast<int16_t>((d >> (6 * j + 3)) & 0x7);

            polynomial[4 * i + j] = a - b;
        }
    }       
}

inline void noise_polynomial_eta1(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, KYBER_ETA1 * KYBER_N / 4> buffer
)
{
#if KYBER_ETA1 == 2
    noise_polynomial_cbd2(polynomial, buffer);
#elif KYBER_ETA1 == 3
    noise_polynomial_cbd3(polynomial, buffer);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

inline void noise_polynomial_eta2(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, KYBER_ETA2 * KYBER_N / 4> buffer
) 
{
#if KYBER_ETA2 == 2
    noise_polynomial_cbd2(polynomial, buffer);
#else
#error "This implementation requires eta2 = 2"
#endif
}


inline void compress(std::span<uint8_t, 128> compressed, std::span<const int16_t, KYBER_N> buffer) {
    uint8_t buf[8];

    for (size_t i = 0; i < KYBER_N / 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            int16_t u = buffer[8 * i + j];
            u += (u >> 15) & KYBER_Q;

            uint32_t d0 = static_cast<uint32_t>(u) << 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            buf[j] = static_cast<uint8_t>(d0 & 0x0F);
        }

        // Pack eight 4-bit values into 4 bytes
        const size_t offset = 4 * i;
        compressed[offset + 0] = static_cast<uint8_t>(buf[0] | (buf[1] << 4));
        compressed[offset + 1] = static_cast<uint8_t>(buf[2] | (buf[3] << 4));
        compressed[offset + 2] = static_cast<uint8_t>(buf[4] | (buf[5] << 4));
        compressed[offset + 3] = static_cast<uint8_t>(buf[6] | (buf[7] << 4));
    }
}


inline void compress(std::span<uint8_t, 160> compressed, std::span<const int16_t, KYBER_N> buffer) {
    uint8_t t[8];

    for (size_t i = 0; i < KYBER_N / 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            int16_t u = buffer[8 * i + j];
            u += (u >> 15) & KYBER_Q;

            uint32_t d0 = static_cast<uint32_t>(u) << 5;
            d0 += 1664;
            d0 *= 40318;
            d0 >>= 27;
            t[j] = static_cast<uint8_t>(d0 & 0x1F);
        }

        const size_t offset = 5 * i;
        compressed[offset + 0] = static_cast<uint8_t>((t[0] >> 0) | (t[1] << 5));
        compressed[offset + 1] = static_cast<uint8_t>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
        compressed[offset + 2] = static_cast<uint8_t>((t[3] >> 1) | (t[4] << 4));
        compressed[offset + 3] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
        compressed[offset + 4] = static_cast<uint8_t>((t[6] >> 2) | (t[7] << 3));
    }
}


inline void compress(std::span<uint8_t, KYBER_POLYVECCOMPRESSEDBYTES> r, 
                      std::span<const int16_t, KYBER_K * KYBER_N> a) {
    size_t out_idx = 0;
    uint64_t d0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
    uint16_t t[8];
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N / 8; j++) {
            for (size_t k = 0; k < 8; k++) {
                t[k] = a[i * KYBER_N + 8 * j + k];
                t[k] += (static_cast<int16_t>(t[k]) >> 15) & KYBER_Q;
                
                d0 = t[k];
                d0 <<= 11;
                d0 += 1664;
                d0 *= 645084;
                d0 >>= 31;
                t[k] = d0 & 0x7ff;
            }

            r[out_idx + 0]  = (t[0] >> 0);
            r[out_idx + 1]  = (t[0] >> 8) | (t[1] << 3);
            r[out_idx + 2]  = (t[1] >> 5) | (t[2] << 6);
            r[out_idx + 3]  = (t[2] >> 2);
            r[out_idx + 4]  = (t[2] >> 10) | (t[3] << 1);
            r[out_idx + 5]  = (t[3] >> 7) | (t[4] << 4);
            r[out_idx + 6]  = (t[4] >> 4) | (t[5] << 7);
            r[out_idx + 7]  = (t[5] >> 1);
            r[out_idx + 8]  = (t[5] >> 9) | (t[6] << 2);
            r[out_idx + 9]  = (t[6] >> 6) | (t[7] << 5);
            r[out_idx + 10] = (t[7] >> 3);
            out_idx += 11;
        }
    }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
    uint16_t t[4];
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N / 4; j++) {
            for (size_t k = 0; k < 4; k++) {
                t[k] = a[i * KYBER_N + 4 * j + k];
                t[k] += (static_cast<int16_t>(t[k]) >> 15) & KYBER_Q;
                
                d0 = t[k];
                d0 <<= 10;
                d0 += 1665;
                d0 *= 1290167;
                d0 >>= 32;
                t[k] = d0 & 0x3ff;
            }

            r[out_idx + 0] = (t[0] >> 0);
            r[out_idx + 1] = (t[0] >> 8) | (t[1] << 2);
            r[out_idx + 2] = (t[1] >> 6) | (t[2] << 4);
            r[out_idx + 3] = (t[2] >> 4) | (t[3] << 6);
            r[out_idx + 4] = (t[3] >> 2);
            out_idx += 5;
        }
    }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

inline void decompress(std::span<int16_t, KYBER_N> decompressed, std::span<const uint8_t, 128> compressed) {
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        uint8_t byte = compressed[i]; 
        
        decompressed[2 * i + 0] = static_cast<int16_t>(((static_cast<uint16_t>(byte & 0x0F) * KYBER_Q) + 8) >> 4);
        
        decompressed[2 * i + 1] = static_cast<int16_t>(((static_cast<uint16_t>(byte >> 4) * KYBER_Q) + 8) >> 4);
    }
}


inline void decompress(std::span<int16_t, KYBER_N> r, std::span<const uint8_t, 160> a) {
    uint8_t t[8];

    for (size_t i = 0; i < KYBER_N / 8; i++) {
        const size_t offset = 5 * i;

        t[0] = (a[offset + 0] >> 0);
        t[1] = (a[offset + 0] >> 5) | (a[offset + 1] << 3);
        t[2] = (a[offset + 1] >> 2);
        t[3] = (a[offset + 1] >> 7) | (a[offset + 2] << 1);
        t[4] = (a[offset + 2] >> 4) | (a[offset + 3] << 4);
        t[5] = (a[offset + 3] >> 1);
        t[6] = (a[offset + 3] >> 6) | (a[offset + 4] << 2);
        t[7] = (a[offset + 4] >> 3);

        for (size_t j = 0; j < 8; j++) {
            r[8 * i + j] = static_cast<int16_t>(((static_cast<uint32_t>(t[j] & 0x1F) * KYBER_Q) + 16) >> 5);
        }
    }
}

inline void polyvec_decompress(std::span<int16_t, KYBER_K * KYBER_N> r, 
                        std::span<const uint8_t, KYBER_POLYVECCOMPRESSEDBYTES> a)
{
    size_t in_idx = 0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
    uint16_t t[8];
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N / 8; j++) {
            t[0] = (a[in_idx + 0] >> 0) | (static_cast<uint16_t>(a[in_idx + 1]) << 8);
            t[1] = (a[in_idx + 1] >> 3) | (static_cast<uint16_t>(a[in_idx + 2]) << 5);
            t[2] = (a[in_idx + 2] >> 6) | (static_cast<uint16_t>(a[in_idx + 3]) << 2) | (static_cast<uint16_t>(a[in_idx + 4]) << 10);
            t[3] = (a[in_idx + 4] >> 1) | (static_cast<uint16_t>(a[in_idx + 5]) << 7);
            t[4] = (a[in_idx + 5] >> 4) | (static_cast<uint16_t>(a[in_idx + 6]) << 4);
            t[5] = (a[in_idx + 6] >> 7) | (static_cast<uint16_t>(a[in_idx + 7]) << 1) | (static_cast<uint16_t>(a[in_idx + 8]) << 9);
            t[6] = (a[in_idx + 8] >> 2) | (static_cast<uint16_t>(a[in_idx + 9]) << 6);
            t[7] = (a[in_idx + 9] >> 5) | (static_cast<uint16_t>(a[in_idx + 10]) << 3);
            in_idx += 11;

            for (size_t k = 0; k < 8; k++) {
                r[i * KYBER_N + 8 * j + k] = static_cast<int16_t>(((static_cast<uint32_t>(t[k] & 0x7FF) * KYBER_Q + 1024) >> 11));
            }
        }
    }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
    uint16_t t[4];
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N / 4; j++) {
            t[0] = (a[in_idx + 0] >> 0) | (static_cast<uint16_t>(a[in_idx + 1]) << 8);
            t[1] = (a[in_idx + 1] >> 2) | (static_cast<uint16_t>(a[in_idx + 2]) << 6);
            t[2] = (a[in_idx + 2] >> 4) | (static_cast<uint16_t>(a[in_idx + 3]) << 4);
            t[3] = (a[in_idx + 3] >> 6) | (static_cast<uint16_t>(a[in_idx + 4]) << 2);
            in_idx += 5;

            for (size_t k = 0; k < 4; k++) {
                r[i * KYBER_N + 4 * j + k] = static_cast<int16_t>(((static_cast<uint32_t>(t[k] & 0x3FF) * KYBER_Q + 512) >> 10));
            }
        }
    }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

inline void bytes_from_polynomial(
    std::span<uint8_t, KYBER_POLYBYTES> bytes, 
    std::span<const int16_t, KYBER_N> polynomial
) 
{
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        int16_t c0 = polynomial[2 * i + 0];
        int16_t c1 = polynomial[2 * i + 1];


        c0 += (c0 >> 15) & KYBER_Q;
        c1 += (c1 >> 15) & KYBER_Q;

        uint16_t t0 = static_cast<uint16_t>(c0);
        uint16_t t1 = static_cast<uint16_t>(c1);

        const size_t offset = 3 * i;

        bytes[offset + 0] = static_cast<uint8_t>(t0);
        bytes[offset + 1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
        bytes[offset + 2] = static_cast<uint8_t>(t1 >> 4);
    }
}


inline void bytes_from_polynomialvector(
    std::span<uint8_t, KYBER_K * KYBER_POLYBYTES> bytes, 
    std::span<const int16_t, KYBER_K * KYBER_N> polynomial
) 
{
    for (size_t i = 0; i < KYBER_K; i++) {
        std::span<uint8_t, KYBER_POLYBYTES> r_slice(
            bytes.data() + i * KYBER_POLYBYTES, KYBER_POLYBYTES
        );
        
        std::span<const int16_t, KYBER_N> a_slice(
            polynomial.data() + i * KYBER_N, KYBER_N
        );

        bytes_from_polynomial(r_slice, a_slice);
    }
}

inline void polynomial_from_bytes(
    std::span<int16_t, KYBER_N> polynomial, 
    std::span<const uint8_t, KYBER_POLYBYTES> bytes) 
{
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        const size_t offset = 3 * i;

        uint8_t b0 = bytes[offset + 0];
        uint8_t b1 = bytes[offset + 1];
        uint8_t b2 = bytes[offset + 2];

        polynomial[2 * i + 0] = static_cast<int16_t>(
            (b0 | (static_cast<uint16_t>(b1) << 8)) & 0x0FFF
        );

        polynomial[2 * i + 1] = static_cast<int16_t>(
            ((b1 >> 4) | (static_cast<uint16_t>(b2) << 4)) & 0x0FFF
        );
    }
}


inline void polynomialvector_from_bytes(std::span<int16_t, KYBER_K * KYBER_N> polynomialvector, 
                       std::span<const uint8_t, KYBER_K * KYBER_POLYBYTES> bytes) 
{
    for (size_t i = 0; i < KYBER_K; i++) {
        std::span<int16_t, KYBER_N> r_slice(
            polynomialvector.data() + i * KYBER_N, KYBER_N
        );
        
        std::span<const uint8_t, KYBER_POLYBYTES> a_slice(
            bytes.data() + i * KYBER_POLYBYTES, KYBER_POLYBYTES
        );

        polynomial_from_bytes(r_slice, a_slice);
    }
}



inline void polynomial_from_message(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, KYBER_INDCPA_MSGBYTES> message
) 
{
    constexpr int16_t half_q = (KYBER_Q + 1) / 2; // 1665

    for (size_t i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        for (size_t j = 0; j < 8; j++) {
            int16_t bit = static_cast<int16_t>((message[i] >> j) & 1);
            int16_t mask = -bit;
            polynomial[8 * i + j] = mask & half_q;
        }
    }
}


inline void message_from_polynomial(
    std::span<uint8_t, KYBER_INDCPA_MSGBYTES> message,
    std::span<const int16_t, KYBER_N> polynomial
) 
{
    for (size_t i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        message[i] = 0;
        
        for (size_t j = 0; j < 8; j++) {
            uint32_t t = static_cast<uint32_t>(polynomial[8 * i + j]);
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;

            message[i] |= static_cast<uint8_t>(t << j);
        }
    }
}

inline void reduce(std::span<int16_t, KYBER_N> polynomial) {
    for (size_t i = 0; i < KYBER_N; i++) {
        polynomial[i] = barrett_reduce(polynomial[i]);
    }
}

inline void reduce(std::span<int16_t, KYBER_K * KYBER_N> polynomialvector) {
    for (size_t i = 0; i < KYBER_K * KYBER_N; ++i)
        polynomialvector[i] = barrett_reduce(polynomialvector[i]);
}

inline void cbd_noise_polynomial_eta1(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, KYBER_SYMBYTES> seed,
    uint8_t nonce
) 
{
    std::array<uint8_t, KYBER_ETA1 * KYBER_N / 4> buffer;
    kyber_shake256_prf(buffer, seed, nonce);
    noise_polynomial_eta1(polynomial, buffer);
}

inline void cbd_noise_polynomial_eta2(
    std::span<int16_t, KYBER_N> polynomial,
    std::span<const uint8_t, KYBER_SYMBYTES> seed, 
    uint8_t nonce
) 
{
    std::array<uint8_t, KYBER_ETA2 * KYBER_N / 4> buf;
    kyber_shake256_prf(buf, seed, nonce);
    noise_polynomial_eta2(polynomial, buf);
}

inline void cbd_noise_polynomialvector_eta1(
    std::span<int16_t, KYBER_K * KYBER_N> polynomialvector,
    std::span<const uint8_t, KYBER_SYMBYTES> seed,
    uint8_t nonce
) 
{
    std::array<uint8_t, KYBER_ETA1 * KYBER_N / 4> buffer;
    
    for (size_t i = 0; i < KYBER_K; i++) {
        kyber_shake256_prf(buffer, seed, nonce++);
        noise_polynomial_eta1(range(polynomialvector, i), buffer);
    }
}

inline void cbd_noise_polynomialvector_eta2(
    std::span<int16_t, KYBER_K * KYBER_N> polynomialvector,
    std::span<const uint8_t, KYBER_SYMBYTES> seed,
    uint8_t nonce
) 
{
    std::array<uint8_t, KYBER_ETA2 * KYBER_N / 4> buffer;
    
    for (size_t i = 0; i < KYBER_K; i++) {
        kyber_shake256_prf(buffer, seed, nonce++);
        noise_polynomial_eta2(range(polynomialvector, i), buffer);
    }
}



inline void polynomial_ntt(std::span<int16_t, KYBER_N> polynomial) {
    ntt_kyber(polynomial);
    reduce(polynomial);
}

inline void polynomialvector_ntt(std::span<int16_t, KYBER_K * KYBER_N> polynomialvector) {
    for (size_t i = 0; i < KYBER_K; i++)
        polynomial_ntt(range(polynomialvector, i));
}


inline void polynomial_intt(std::span<int16_t, KYBER_N> polynomial) {
    intt_kyber(polynomial);
}


inline void polynomialvector_intt(std::span<int16_t, KYBER_K * KYBER_N> polynomialvector) {
    for (size_t i = 0; i < KYBER_K; i++)
        polynomial_intt(range(polynomialvector, i));
}


inline void polynomial_multiplication_ntt_domain(
    std::span<int16_t, KYBER_N> r,
    std::span<const int16_t, KYBER_N> a,
    std::span<const int16_t, KYBER_N> b)
{

    for (size_t i = 64, idx = 0; idx < KYBER_N; idx += 4, ++i) {

        r[idx + 0]  = montgomery_multiplication(a[idx + 1], b[idx + 1]);
        r[idx + 0]  = montgomery_multiplication(r[idx + 0], kyber_zetas[i]);
        r[idx + 0] += montgomery_multiplication(a[idx + 0], b[idx + 0]);

        r[idx + 1]  = montgomery_multiplication(a[idx + 0], b[idx + 1]);
        r[idx + 1] += montgomery_multiplication(a[idx + 1], b[idx + 0]);

        r[idx + 2]  = montgomery_multiplication(a[idx + 3], b[idx + 3]);
        r[idx + 2]  = montgomery_multiplication(r[idx + 2], -kyber_zetas[i]);
        r[idx + 2] += montgomery_multiplication(a[idx + 2], b[idx + 2]);

        r[idx + 3]  = montgomery_multiplication(a[idx + 2], b[idx + 3]);
        r[idx + 3] += montgomery_multiplication(a[idx + 3], b[idx + 2]);
    }
}

inline void montogomery_domain(std::span<int16_t, KYBER_N> polynomial) {
    constexpr int16_t rsquaremodq = (1ULL << 32) % KYBER_Q;
    for (size_t i = 0; i < KYBER_N; i++)
        polynomial[i] = montgomery_multiplication(polynomial[i], rsquaremodq);
}


inline void polynomial_addition(
    std::span<int16_t, KYBER_N> result, 
    std::span<const int16_t, KYBER_N> polynomial1, 
    std::span<const int16_t, KYBER_N> polynomial2
) 
{
    for (size_t i = 0; i < KYBER_N; i++)
        result[i] = polynomial1[i] + polynomial2[i];
}

inline void polynomial_subtraction(
    std::span<int16_t, KYBER_N> result, 
    std::span<const int16_t, KYBER_N> polynomial1, 
    std::span<const int16_t, KYBER_N> polynomial2
) 
{
    for (size_t i = 0; i < KYBER_N; i++)
        result[i] = polynomial1[i] - polynomial2[i];
}


inline void polynomialvector_dotproduct(
    std::span<int16_t, KYBER_N> result, 
    std::span<const int16_t, KYBER_K * KYBER_N> polynomialvector1, 
    std::span<const int16_t, KYBER_K * KYBER_N> polynomialvector2) 
{
    std::array<int16_t, KYBER_N> buffer;
    auto* pv1 = polynomialvector1.data();
    auto* pv2 = polynomialvector2.data();

    polynomial_multiplication_ntt_domain(
        result,
        crange(polynomialvector1, 0),
        crange(polynomialvector2, 0)
    );

    for (size_t i = 1; i < KYBER_K; i++) {
        polynomial_multiplication_ntt_domain(
            buffer, 
            crange(polynomialvector1, i),
            crange(polynomialvector2, i)
        );
        polynomial_addition(result, result, buffer);
    }

    reduce(result);
}


inline void polynomialvector_addition(
    std::span<int16_t, KYBER_K * KYBER_N> result, 
    std::span<const int16_t, KYBER_K * KYBER_N> polynomialvector1, 
    std::span<const int16_t, KYBER_K * KYBER_N> polynomialvector2
) 
{
    for (size_t i = 0; i < KYBER_K * KYBER_N; i++)
        result[i] = polynomialvector1[i] + polynomialvector2[i];
}