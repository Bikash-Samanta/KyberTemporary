#include <cstdint>
#include <array>
#include <span>
#include "params.hpp"


inline int16_t barrett_reduce(int16_t x) {
  constexpr int16_t v = ((1l << 26) + KYBER_Q / 2) / KYBER_Q; // v = round(2^26/q)
  
  int16_t result;
  result  = ((int32_t)v * x + (1<<25)) >> 26; // result = round(x * v / 2^26)
  result *= KYBER_Q;
  return x - result;
} // return value in range [-Q/2, Q/2]

inline constexpr int16_t montgomery_multiplication(int16_t a, int16_t b){
  constexpr int16_t qinv = -3327; // q^-1 mod 2^16
  int32_t T = (int32_t)a * b;
  int16_t m = (int16_t)T * qinv; // m = (T mod R) * q' mod R
  int16_t t = (T - (int32_t)m * KYBER_Q) >> 16; // t = (T - m*q)/R
  return t; // return abR^-1 mod q
} // range of t is [-q+1, q-1]

constexpr std::array<int16_t, 128> construct_Kyber_zetas() {
  auto bitRev7 = [](unsigned char v) -> unsigned char {
    return ((v & 0x01) << 6) |
           ((v & 0x02) << 4) |
           ((v & 0x04) << 2) |
           ((v & 0x08)     ) |
           ((v & 0x10) >> 2) |
           ((v & 0x20) >> 4) |
           ((v & 0x40) >> 6);
  };

  constexpr int16_t zeta = 17;
  constexpr int16_t R = -1044; // 2^16 mod q
  constexpr int16_t zetaR = (zeta * R) % KYBER_Q;
  int16_t zetas_tmp[128]{};
  zetas_tmp[0] = R;

  for (int i = 1; i < 128; ++i)
    zetas_tmp[i] = montgomery_multiplication(zetas_tmp[i - 1], zetaR);

  std::array<int16_t, 128> zetas{};
  for (int i = 0; i < 128; ++i) {
    zetas[i] = zetas_tmp[bitRev7(i)];
    if (zetas[i] > KYBER_Q / 2)
      zetas[i] -= KYBER_Q;
    if (zetas[i] < -KYBER_Q / 2)
      zetas[i] += KYBER_Q;
  }

  return zetas;
}

constexpr std::array<int16_t, 128> kyber_zetas = construct_Kyber_zetas(); // excecution happen in compile time, so no runtime overhead


inline void ntt_kyber(std::span<int16_t, KYBER_N> polynomial) {
  unsigned int len, start, i, k = 1;
  int16_t zeta, res;

  for (len = 128; len >=2; len >>=1) {
    for (start = 0; start < 256; start = i + len) {
      zeta = kyber_zetas[k++];
      for (i = start; i < start + len; ++i) {
        res = montgomery_multiplication(zeta, polynomial[i + len]);
        polynomial[i + len] = polynomial[i] - res;
        polynomial[i] = polynomial[i] + res;
      }
    }
  }
} // if input is in normal domain, output is in normal domain;



inline void intt_kyber(std::span<int16_t, KYBER_N> polynomial) { 
  unsigned int start, len, i, k;
  int16_t res, zeta;
  constexpr int16_t f = 1441; // mont^2/128

  k = 127;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = i + len) {
      zeta = kyber_zetas[k--];
      for(i = start; i < start + len; i++) {
        res = polynomial[i];
        polynomial[i] = barrett_reduce(res + polynomial[i + len]);
        polynomial[i + len] = polynomial[i + len] - res;
        polynomial[i + len] = montgomery_multiplication(zeta, polynomial[i + len]);
      }
    }
  }

  for(i = 0; i < KYBER_N; i++)
    polynomial[i] = montgomery_multiplication(polynomial[i], f);
} // if input is in inverse montgomery domain, output is in normal domain