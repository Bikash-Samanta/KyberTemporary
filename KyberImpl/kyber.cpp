/*
[akaza@akaza KyberImpl]$ g++ -O3 kyber.cpp -o kyber
[akaza@akaza KyberImpl]$ ./kyber
---------- Kyber768 ---------
--- Step 1: Correctness Check ---
[SUCCESS] Decryption working perfectly. Moving to benchmarks.

--- Step 2: Performance Benchmarking ---
Cycle counting overhead: 1 cycles
Running 10000 iterations...

=== Performance Results (CPU Cycles) ===
[Key Generation]
  Median:  86368
  Average: 87508
[Encryption]
  Median:  99539
  Average: 100804
[Decryption]
  Median:  18899
  Average: 19137
[akaza@akaza KyberImpl]$ ./kyber
---------- Kyber768 ---------
--- Step 1: Correctness Check ---
[SUCCESS] Decryption working perfectly. Moving to benchmarks.

--- Step 2: Performance Benchmarking ---
Cycle counting overhead: 60 cycles
Running 10000 iterations...

=== Performance Results (CPU Cycles) ===
[Key Generation]
  Median:  86250
  Average: 86935
[Encryption]
  Median:  99510
  Average: 100249
[Decryption]
  Median:  18840
  Average: 18946
[akaza@akaza KyberImpl]$ ./kyber
---------- Kyber768 ---------
--- Step 1: Correctness Check ---
[SUCCESS] Decryption working perfectly. Moving to benchmarks.

--- Step 2: Performance Benchmarking ---
Cycle counting overhead: 60 cycles
Running 10000 iterations...

=== Performance Results (CPU Cycles) ===
[Key Generation]
  Median:  86460
  Average: 88345
[Encryption]
  Median:  99540
  Average: 101709
[Decryption]
  Median:  18810
  Average: 19221
[akaza@akaza KyberImpl]$ 
*/

#include <iostream>
#include <array>
#include <span>
#include <vector>
#include <cstdint>
#include "params.hpp"
#include "kyber.hpp"
#include "cpucycles.hpp"

const int NTESTS = 10000;

// Helper function to calculate median cycles (filters out OS interrupts)
uint64_t median(std::vector<uint64_t>& cycles) {
    std::sort(cycles.begin(), cycles.end());
    return cycles[cycles.size() / 2];
}

// Helper function to calculate average cycles
uint64_t average(const std::vector<uint64_t>& cycles) {
    uint64_t sum = 0;
    for (uint64_t c : cycles) sum += c;
    return sum / cycles.size();
}

int main() {
    std::array<uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> pk = {0};
    std::array<uint8_t, KYBER_INDCPA_SECRETKEYBYTES> sk = {0};
    
    std::array<uint8_t, KYBER_SYMBYTES> keypair_coins = {0};
    std::array<uint8_t, KYBER_SYMBYTES> enc_coins = {0};
    std::array<uint8_t, KYBER_INDCPA_MSGBYTES> msg = {0};
    
    std::array<uint8_t, KYBER_INDCPA_BYTES> ciphertext = {0};
    std::array<uint8_t, KYBER_INDCPA_MSGBYTES> decrypted_msg = {0};

    // Initialize deterministic dummy data
    for (size_t i = 0; i < KYBER_SYMBYTES; i++) {
        keypair_coins[i] = static_cast<uint8_t>(i);
        enc_coins[i]     = static_cast<uint8_t>(i + 42);
    }
    for (size_t i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        msg[i] = static_cast<uint8_t>(0xAB ^ i);
    }

    std::cout << "---------- Kyber768 ---------" << std::endl;

    std::cout << "--- Step 1: Correctness Check ---" << std::endl;
    
    keygeneration_pk_sk(pk, sk, keypair_coins);
    kyber_enc(ciphertext, msg, pk, enc_coins);
    kyber_dec(decrypted_msg, ciphertext, sk);

    // Verify
    bool success = true;
    for (size_t i = 0; i < KYBER_INDCPA_MSGBYTES; i++) {
        if (msg[i] != decrypted_msg[i]) {
            success = false;
            break;
        }
    }

    if (!success) {
        std::cerr << "[ERROR] Decryption failed! Aborting performance tests." << std::endl;
        return 1;
    }
    
    std::cout << "[SUCCESS] Decryption working perfectly. Moving to benchmarks.\n" << std::endl;

    std::cout << "--- Step 2: Performance Benchmarking ---" << std::endl;

    std::vector<uint64_t> cycles_keygen(NTESTS);
    std::vector<uint64_t> cycles_enc(NTESTS);
    std::vector<uint64_t> cycles_dec(NTESTS);

    uint64_t t0, t1;
    uint64_t overhead = cpucycles_overhead();
    
    std::cout << "Cycle counting overhead: " << overhead << " cycles" << std::endl;
    std::cout << "Running " << NTESTS << " iterations..." << std::endl;

    for (int i = 0; i < NTESTS; i++) {
        // --- Benchmark Key Generation ---
        t0 = cpucycles();
        keygeneration_pk_sk(pk, sk, keypair_coins);
        t1 = cpucycles();
        cycles_keygen[i] = (t1 - t0) - overhead;

        // --- Benchmark Encryption ---
        t0 = cpucycles();
        kyber_enc(ciphertext, msg, pk, enc_coins);
        t1 = cpucycles();
        cycles_enc[i] = (t1 - t0) - overhead;

        // --- Benchmark Decryption ---
        t0 = cpucycles();
        kyber_dec(decrypted_msg, ciphertext, sk);
        t1 = cpucycles();
        cycles_dec[i] = (t1 - t0) - overhead;
        
        // Cycle dummy data slightly so the optimizer doesn't cache results
        keypair_coins[0]++;
        enc_coins[0]++;
        msg[0]++;
    }

    // Print Statistics
    std::cout << "\n=== Performance Results (CPU Cycles) ===" << std::endl;
    
    std::cout << "[Key Generation]" << "\n";
    std::cout << "  Median:  " << median(cycles_keygen) << "\n";
    std::cout << "  Average: " << average(cycles_keygen) << "\n";

    std::cout << "[Encryption]" << "\n";
    std::cout << "  Median:  " << median(cycles_enc) << "\n";
    std::cout << "  Average: " << average(cycles_enc) << "\n";

    std::cout << "[Decryption]" << "\n";
    std::cout << "  Median:  " << median(cycles_dec) << "\n";
    std::cout << "  Average: " << average(cycles_dec) << "\n";

    return 0;
}