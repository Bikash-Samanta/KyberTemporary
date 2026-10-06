#pragma once

#include "kyber_pke.hpp"
#include "random.hpp"

inline int verify(const uint8_t *a, const uint8_t *b, size_t len) {
  size_t i;
  uint8_t r = 0;

  for(i=0;i<len;i++)
    r |= a[i] ^ b[i];

  return (-(uint64_t)r) >> 63;
}

inline void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
  size_t i;

#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(b) : /* no inputs */);
#endif

  b = -b;
  for(i=0;i<len;i++)
    r[i] ^= b & (r[i] ^ x[i]);
}

inline void cmov_int16(int16_t *r, int16_t v, uint16_t b) {
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(b) : /* no inputs */);
#endif

  b = -b;
  *r ^= b & ((*r) ^ v);
}

inline void kem_keypair_derand(
    std::span<uint8_t, KYBER_PUBLICKEYBYTES> public_key,
    std::span<uint8_t, KYBER_SECRETKEYBYTES> secret_key,
    std::span<const uint8_t, 2 * KYBER_SYMBYTES> seed
)
{
    auto kyberpke_sk = secret_key.first<KYBER_INDCPA_SECRETKEYBYTES>();
    auto keygen_seed = seed.first<KYBER_SYMBYTES>();

    kyber_pke_keypair(public_key, kyberpke_sk, keygen_seed);

    auto stored_pk = secret_key.subspan<KYBER_INDCPA_SECRETKEYBYTES, KYBER_PUBLICKEYBYTES>();
    std::copy(public_key.begin(), public_key.end(), stored_pk.begin());

    auto hpk = secret_key.subspan<KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES>();
    sha3_256(hpk, public_key.subspan<0, KYBER_PUBLICKEYBYTES>());

    auto z = secret_key.subspan<KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES>();
    auto seed_z = seed.subspan<KYBER_SYMBYTES>();
    std::copy(seed_z.begin(), seed_z.end(), z.begin());
}

inline void kyber_kem_keypair(
    std::span<uint8_t, KYBER_PUBLICKEYBYTES> public_key,
    std::span<uint8_t, KYBER_SECRETKEYBYTES> secret_key
)
{
    std::array<uint8_t, 2 * KYBER_SYMBYTES> seed{};
    randombytes(seed);
    kem_keypair_derand(public_key, secret_key, seed);
}

inline void kem_enc_derand(
    std::span<uint8_t, KYBER_CIPHERTEXTBYTES> ciphertext,
    std::span<uint8_t, KYBER_SSBYTES> shared_secret,
    std::span<const uint8_t, KYBER_PUBLICKEYBYTES> public_key,
    std::span<const uint8_t, KYBER_SYMBYTES> seed
)
{
    std::array<uint8_t, 2 * KYBER_SYMBYTES> buf{};
    std::array<uint8_t, 2 * KYBER_SYMBYTES> kr{};
    
    std::span<uint8_t, KYBER_SYMBYTES> buf_view(buf.data() + KYBER_SYMBYTES, KYBER_SYMBYTES);
    std::copy(seed.begin(), seed.end(), buf.begin());
    
    sha3_256(buf_view, public_key.subspan<0, KYBER_PUBLICKEYBYTES>());
    sha3_512(kr, buf);
    
    auto message = std::span<const uint8_t, KYBER_SYMBYTES>(buf.data(), KYBER_SYMBYTES);
    auto encapsulation_coins = std::span<const uint8_t, KYBER_SYMBYTES>(kr.data() + KYBER_SYMBYTES, KYBER_SYMBYTES);

    kyber_pke_enc(ciphertext, message, public_key, encapsulation_coins);
    
    auto K = std::span<const uint8_t, KYBER_SYMBYTES>(kr.data(), KYBER_SYMBYTES);
    std::copy(K.begin(), K.end(), shared_secret.begin());
}

inline void kyber_kem_enc(
    std::span<uint8_t, KYBER_CIPHERTEXTBYTES> ciphertext,
    std::span<uint8_t, KYBER_SSBYTES> shared_secret,
    std::span<const uint8_t, KYBER_PUBLICKEYBYTES> public_key)
{
    std::array<uint8_t, KYBER_SYMBYTES> seed{};
    randombytes(seed);
    kem_enc_derand(ciphertext, shared_secret, public_key, seed);
}

inline void kyber_kem_dec(
    std::span<uint8_t, KYBER_SSBYTES> shared_secret,
    std::span<const uint8_t, KYBER_CIPHERTEXTBYTES> ciphertext,
    std::span<const uint8_t, KYBER_SECRETKEYBYTES> secret_key)
{
    std::array<uint8_t, 2 * KYBER_SYMBYTES> buf{};
    std::array<uint8_t, 2 * KYBER_SYMBYTES> kr{};
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> cmp{};

    auto indcpa_sk = secret_key.first<KYBER_INDCPA_SECRETKEYBYTES>();
    auto public_key = secret_key.subspan<KYBER_INDCPA_SECRETKEYBYTES, KYBER_PUBLICKEYBYTES>();

    auto message = std::span<uint8_t, KYBER_INDCPA_MSGBYTES>(buf.data(), KYBER_INDCPA_MSGBYTES);
    kyber_pke_dec(message, ciphertext, indcpa_sk);

    auto hpk = secret_key.subspan<KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, KYBER_SYMBYTES>();
    std::copy(hpk.begin(), hpk.end(), buf.begin() + KYBER_SYMBYTES);

    sha3_512(kr, buf);

    auto reencryption_seed = std::span<const uint8_t, KYBER_SYMBYTES>(kr.data() + KYBER_SYMBYTES, KYBER_SYMBYTES);

    kyber_pke_enc(
        std::span<uint8_t, KYBER_CIPHERTEXTBYTES>(cmp.data(), cmp.size()),
        std::span<const uint8_t, KYBER_INDCPA_MSGBYTES>(buf.data(), KYBER_INDCPA_MSGBYTES),
        public_key,
        reencryption_seed
    );

    const int fail = verify(ciphertext.data(), cmp.data(), KYBER_CIPHERTEXTBYTES);

    auto z = secret_key.subspan<KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES>();
    kyber_shake256_rkprf(shared_secret, z, ciphertext);

    cmov(shared_secret.data(), kr.data(), KYBER_SYMBYTES, !fail);
}