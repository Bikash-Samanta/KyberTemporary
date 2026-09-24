#pragma once

#include <cstdint>
#include <array>
#include <algorithm>
#include <span>
#include "params.hpp"
#include "fips202.hpp"

typedef keccak_state xof_state;

// 1. Updated declarations to perfectly match the span definitions
#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *state,
                           std::span<const uint8_t, KYBER_SYMBYTES> seed,
                           uint8_t x,
                           uint8_t y);


#define kyber_shake256_rkprf KYBER_NAMESPACE(kyber_shake256_rkprf)
void kyber_shake256_rkprf(std::span<uint8_t, KYBER_SSBYTES> out, 
                          std::span<const uint8_t, KYBER_SYMBYTES> key, 
                          std::span<const uint8_t, KYBER_CIPHERTEXTBYTES> input);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

// 2. Dropped the redundant OUTBYTES parameter from the prf call
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) kyber_shake256_rkprf(OUT, KEY, INPUT)


// 3. Added 'inline' so this header can be included safely in multiple files
inline void kyber_shake128_absorb(keccak_state *state,
                                  std::span<const uint8_t, KYBER_SYMBYTES> seed,
                                  uint8_t x,
                                  uint8_t y) {
    std::array<uint8_t, KYBER_SYMBYTES + 2> extseed;

    std::copy(seed.begin(), seed.end(), extseed.begin());
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;

    shake128_absorb_once(state, extseed.data(), extseed.size());
}

inline void kyber_shake256_prf(std::span<uint8_t> out, 
                               std::span<const uint8_t, KYBER_SYMBYTES> key, 
                               uint8_t nonce) {
    std::array<uint8_t, KYBER_SYMBYTES + 1> extkey;

    std::copy(key.begin(), key.end(), extkey.begin());
    extkey[KYBER_SYMBYTES] = nonce;

    shake256(out.data(), out.size(), extkey.data(), extkey.size());
}

inline void kyber_shake256_rkprf(std::span<uint8_t, KYBER_SSBYTES> out, 
                                 std::span<const uint8_t, KYBER_SYMBYTES> key, 
                                 std::span<const uint8_t, KYBER_CIPHERTEXTBYTES> input) {
    keccak_state s;

    shake256_init(&s);
    shake256_absorb(&s, key.data(), key.size());
    shake256_absorb(&s, input.data(), input.size());
    shake256_finalize(&s);
    shake256_squeeze(out.data(), out.size(), &s);
}