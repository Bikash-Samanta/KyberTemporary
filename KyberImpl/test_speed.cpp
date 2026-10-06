#include <array>
#include <concepts>
#include <cstdint>
#include <functional>
#include <string_view>
#include <span>
#include <print>
#include "kyber_kem.hpp"
#include "cpucycles.hpp"

/*

[akaza@akaza KyberImpl]$ g++ -std=c++26 -O3 test_speed.cpp -o test_speed
[akaza@akaza KyberImpl]$ ./test_speed
Operation                      |   Median |       Mean |      Min |      Max
-------------------------------+----------+------------+----------+----------
kyber_pke_keypair:             |    76950 |  108051.87 |    76680 |   282720
kyber_pke_enc:                 |    90000 |   91463.55 |    89700 |   138930
kyber_pke_dec:                 |    18930 |   19227.66 |    18870 |    57150
kyber_kem_keypair:             |    98220 |   99788.36 |    96660 |   147270
kyber_kem_enc:                 |   102000 |  103867.37 |   101310 |   211650
kyber_kem_dec:                 |   123060 |  124885.00 |   122010 |   175590
poly_compress:                 |      360 |     408.11 |      359 |    37650
poly_decompress:               |       30 |      28.20 |        1 |       30
polyvec_compress:              |     2699 |    2694.65 |     2670 |     3480
polyvec_decompress:            |     1710 |    1710.11 |     1709 |     1860
bytes_from_polynomial:         |      450 |     442.14 |      420 |      480
polynomial_from_bytes:         |      360 |     360.09 |      360 |      390
bytes_from_polynomialvector:   |     1290 |    1293.41 |     1260 |     1920
polynomialvector_from_bytes:   |     1080 |    1079.47 |     1050 |     1110

[akaza@akaza KyberImpl]$ ./test_speed
Operation                      |   Median |       Mean |      Min |      Max
-------------------------------+----------+------------+----------+----------
kyber_pke_keypair:             |    76770 |  108867.57 |    76560 |   320490
kyber_pke_enc:                 |    89550 |   90795.57 |    89250 |   130470
kyber_pke_dec:                 |    18960 |   19223.49 |    18870 |    56580
kyber_kem_keypair:             |    98310 |   99585.62 |    96540 |   137790
kyber_kem_enc:                 |   102120 |  108553.18 |   101460 |   383400
kyber_kem_dec:                 |   122910 |  131234.32 |   122250 |   732720
poly_compress:                 |      360 |     363.23 |      360 |      630
poly_decompress:               |       30 |      27.86 |        1 |       30
polyvec_compress:              |     2670 |    2989.88 |     2640 |    66449
polyvec_decompress:            |     1740 |    1955.81 |     1710 |    36360
bytes_from_polynomial:         |      420 |     434.32 |      420 |      450
polynomial_from_bytes:         |      360 |     367.20 |      360 |      390
bytes_from_polynomialvector:   |     1290 |    1430.68 |     1260 |    34470
polynomialvector_from_bytes:   |     1080 |    1084.46 |     1080 |     1140

[akaza@akaza KyberImpl]$ ./test_speed
Operation                      |   Median |       Mean |      Min |      Max
-------------------------------+----------+------------+----------+----------
kyber_pke_keypair:             |    76800 |  105036.28 |    76530 |   395220
kyber_pke_enc:                 |    89790 |   91029.85 |    89430 |   178680
kyber_pke_dec:                 |    19080 |   19333.53 |    18990 |    54090
kyber_kem_keypair:             |    98430 |   99676.68 |    96930 |   136290
kyber_kem_enc:                 |   101940 |  103438.32 |   101610 |   147810
kyber_kem_dec:                 |   122550 |  124972.62 |   122190 |   192510
poly_compress:                 |      360 |     400.62 |      360 |    33900
poly_decompress:               |       30 |      28.17 |        1 |       30
polyvec_compress:              |     2670 |    2724.63 |     2670 |    34380
polyvec_decompress:            |     1920 |    1909.55 |     1890 |     2040
bytes_from_polynomial:         |      600 |     599.98 |      599 |      630
polynomial_from_bytes:         |      510 |     531.68 |      480 |    29789
bytes_from_polynomialvector:   |     1800 |    1813.88 |     1800 |     2280
polynomialvector_from_bytes:   |     1080 |    1295.31 |     1050 |    41310
[akaza@akaza KyberImpl]$ 

*/

constexpr size_t NTESTS = 1000;

inline void print_results(std::string_view name, std::span<uint64_t> timings) 
{
    if (timings.empty()) return;

    std::ranges::sort(timings);

    uint64_t min_cycles    = timings.front();
    uint64_t max_cycles    = timings.back();
    uint64_t median_cycles = timings[timings.size() / 2];

    double sum = 0.0;
    for (uint64_t t : timings)
        sum += static_cast<double>(t);

    double mean_cycles = sum / timings.size();

    static bool header_printed = false;
    if (!header_printed) {
        std::println("{:<30} | {:>8} | {:>10} | {:>8} | {:>8}",
                     "Operation", "Median", "Mean", "Min", "Max");
        std::println("-------------------------------+----------+------------+----------+----------");
        header_printed = true;
    }


    std::println("{:<30} | {:>8} | {:>10.2f} | {:>8} | {:>8}",
                 name, median_cycles, mean_cycles, min_cycles, max_cycles);
}

template <std::invocable Func>
void measure_speed(std::string_view name, Func&& func) 
{
    std::array<uint64_t, NTESTS> timings{};
    
    std::invoke(func);
    
    for (size_t i = 0; i < NTESTS; ++i) {
        uint64_t start = cpucycles();
        std::invoke(std::forward<Func>(func));
        uint64_t end = cpucycles();
        
        timings[i] = end - start;
    }
    
    print_results(name, timings);
}


int main() 
{
    std::array<uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> pke_pk{};
    std::array<uint8_t, KYBER_INDCPA_SECRETKEYBYTES> pke_sk{};
    std::array<uint8_t, KYBER_INDCPA_BYTES>          pke_ct{};
    std::array<uint8_t, KYBER_INDCPA_MSGBYTES>       pke_msg{};
    std::array<uint8_t, KYBER_SYMBYTES>              pke_seed{};

    std::array<uint8_t, KYBER_PUBLICKEYBYTES>  kem_pk{};
    std::array<uint8_t, KYBER_SECRETKEYBYTES>  kem_sk{};
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> kem_ct{};
    std::array<uint8_t, KYBER_SSBYTES>         kem_ss{};

    std::array<uint8_t, KYBER_POLYCOMPRESSEDBYTES>    poly_comp{};
    std::array<uint8_t, KYBER_POLYVECCOMPRESSEDBYTES> polyvec_comp{};
    
    std::array<uint8_t, KYBER_POLYBYTES>    poly_bytes{};
    std::array<uint8_t, KYBER_POLYVECBYTES> polyvec_bytes{};

    std::array<int16_t, KYBER_N>           ap{};
    std::array<int16_t, KYBER_K * KYBER_N> pv{};

    randombytes(pke_msg);
    randombytes(pke_seed);

    measure_speed("kyber_pke_keypair: ", [&] { 
        kyber_pke_keypair(pke_pk, pke_sk, pke_seed); 
    });

    measure_speed("kyber_pke_enc: ", [&] { 
        kyber_pke_enc(pke_ct, pke_msg, pke_pk, pke_seed); 
    });

    measure_speed("kyber_pke_dec: ", [&] { 
        kyber_pke_dec(pke_msg, pke_ct, pke_sk); 
    });

    measure_speed("kyber_kem_keypair: ", [&] { 
        kyber_kem_keypair(kem_pk, kem_sk); 
    });

    measure_speed("kyber_kem_enc: ", [&] { 
        kyber_kem_enc(kem_ct, kem_ss, kem_pk); 
    });

    measure_speed("kyber_kem_dec: ", [&] { 
        kyber_kem_dec(kem_ss, kem_ct, kem_sk); 
    });

    measure_speed("poly_compress: ", [&] { 
        compress(poly_comp, ap); 
    });

    measure_speed("poly_decompress: ", [&] { 
        decompress(ap, poly_comp); 
    });

    measure_speed("polyvec_compress: ", [&] { 
        polyvec_compress(polyvec_comp, pv); 
    });

    measure_speed("polyvec_decompress: ", [&] { 
        polyvec_decompress(pv, polyvec_comp); 
    });

    measure_speed("bytes_from_polynomial: ", [&] { 
        bytes_from_polynomial(poly_bytes, ap); 
    });

    measure_speed("polynomial_from_bytes: ", [&] { 
        polynomial_from_bytes(ap, poly_bytes); 
    });

    measure_speed("bytes_from_polynomialvector: ", [&] { 
        bytes_from_polynomialvector(polyvec_bytes, pv); 
    });

    measure_speed("polynomialvector_from_bytes: ", [&] { 
        polynomialvector_from_bytes(pv, polyvec_bytes); 
    });

    return 0;
}