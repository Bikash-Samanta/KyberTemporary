#pragma once

#include "kyber_pke.hpp"



inline void keygeneration_pk_sk(
    std::span<uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> public_key,
    std::span<uint8_t, KYBER_INDCPA_SECRETKEYBYTES> secret_key,
    std::span<const uint8_t, KYBER_SYMBYTES> seed
);


inline void kyber_enc(std::span<uint8_t, KYBER_INDCPA_BYTES> ciphertext,
                std::span<const uint8_t, KYBER_INDCPA_MSGBYTES> message,
                std::span<const uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> public_key,
                std::span<const uint8_t, KYBER_SYMBYTES> seed);


inline void kyber_dec(std::span<uint8_t, KYBER_INDCPA_MSGBYTES> decrypted_message,
                std::span<const uint8_t, KYBER_INDCPA_BYTES> ciphertext,
                std::span<const uint8_t, KYBER_INDCPA_SECRETKEYBYTES> secret_key);        