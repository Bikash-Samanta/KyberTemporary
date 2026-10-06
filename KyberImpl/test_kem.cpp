/*
[akaza@akaza KyberImpl]$ g++ -std=c++26 -O3 test_kem.cpp -o test_kem
[akaza@akaza KyberImpl]$ ./test_kem
--- Kyber KEM Configuration ---
KYBER_SECRETKEYBYTES:  2400
KYBER_PUBLICKEYBYTES:  1184
KYBER_CIPHERTEXTBYTES: 1088
-------------------------------
SUCCESS: All 1000 tests passed without any errors!
[akaza@akaza KyberImpl]$ 
*/


#include "kyber_kem.hpp"
#include "params.hpp"
#include <print>
#include <algorithm>
#include <array>


constexpr size_t NTESTS = 1000;

[[nodiscard]] static bool test_keys() 
{
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> pk;
    std::array<uint8_t, KYBER_SECRETKEYBYTES> sk;
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> ct;
    std::array<uint8_t, KYBER_SSBYTES> key_a;
    std::array<uint8_t, KYBER_SSBYTES> key_b;

    kyber_kem_keypair(pk, sk);
    kyber_kem_enc(ct, key_b, pk);
    kyber_kem_dec(key_a, ct, sk);

    if (!std::equal(key_a.begin(), key_a.end(), key_b.begin())) {
        std::println(stderr, "ERROR (test_keys): Decapsulated secret does not match the encapsulated secret.");
        return false;
    }

    return true;
}

[[nodiscard]] static bool test_invalid_sk_a() 
{
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> pk;
    std::array<uint8_t, KYBER_SECRETKEYBYTES> sk;
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> ct;
    std::array<uint8_t, KYBER_SSBYTES> key_a;
    std::array<uint8_t, KYBER_SSBYTES> key_b;

    kyber_kem_keypair(pk, sk);
    kyber_kem_enc(ct, key_b, pk);

    randombytes(sk);

    kyber_kem_dec(key_a, ct, sk);

    if (std::equal(key_a.begin(), key_a.end(), key_b.begin())) {
        std::println(stderr, "ERROR (test_invalid_sk_a): Invalid secret key still produced the valid shared secret. Implicit rejection failed!");
        return false;
    }

    return true;
}

[[nodiscard]] static bool test_invalid_ciphertext() 
{
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> pk;
    std::array<uint8_t, KYBER_SECRETKEYBYTES> sk;
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> ct;
    std::array<uint8_t, KYBER_SSBYTES> key_a;
    std::array<uint8_t, KYBER_SSBYTES> key_b;

    uint8_t b = 0;
    std::array<uint8_t, 1> rand_byte{};
    while (b == 0) {
        randombytes(rand_byte);
        b = rand_byte[0];
    }

    size_t pos = 0;
    std::array<uint8_t, sizeof(pos)> pos_bytes{};
    randombytes(pos_bytes);
    std::copy(pos_bytes.begin(), pos_bytes.end(), reinterpret_cast<uint8_t*>(&pos));

    kyber_kem_keypair(pk, sk);
    kyber_kem_enc(ct, key_b, pk);

    ct[pos % KYBER_CIPHERTEXTBYTES] ^= b;

    kyber_kem_dec(key_a, ct, sk);

    if (std::equal(key_a.begin(), key_a.end(), key_b.begin())) {
        std::println(stderr, "ERROR (test_invalid_ciphertext): Corrupted ciphertext still produced the valid shared secret. CCA security check failed!");
        return false;
    }

    return true;
}

int main() 
{
    bool success = true;

    for (size_t i = 0; i < NTESTS; ++i) {
        if (!test_keys()) {
            std::println(stderr, "Test Failure at iteration {}: Normal keypair/encaps/decaps failed.", i);
            success = false;
            break;
        }
        if (!test_invalid_sk_a()) {
            std::println(stderr, "Test Failure at iteration {}: Invalid secret key verification failed.", i);
            success = false;
            break;
        }
        if (!test_invalid_ciphertext()) {
            std::println(stderr, "Test Failure at iteration {}: Invalid ciphertext verification failed.", i);
            success = false;
            break;
        }
    }

    std::println("--- Kyber KEM Configuration ---");
    std::println("KYBER_SECRETKEYBYTES:  {}", KYBER_SECRETKEYBYTES);
    std::println("KYBER_PUBLICKEYBYTES:  {}", KYBER_PUBLICKEYBYTES);
    std::println("KYBER_CIPHERTEXTBYTES: {}", KYBER_CIPHERTEXTBYTES);
    std::println("-------------------------------");

    if (success) {
        std::println("SUCCESS: All {} tests passed without any errors!", NTESTS);
        return 0;
    } else {
        std::println(stderr, "FAILURE: Kyber KEM tests encountered errors. Check the output above for the specific problem.");
        return 1;
    }
}