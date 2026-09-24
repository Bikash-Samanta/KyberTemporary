#include "kyber_prerequisites.hpp"

// Define array capacities based on the security level K (2, 3, or 4)
// t = A * s + e, where A is K x K matrix of polynomials, s and e are vectors of K polynomials

static void pack_pk(std::span<uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> r,
                    std::span<const int16_t, KYBER_K * KYBER_N> pk,
                    std::span<const uint8_t, KYBER_SYMBYTES> seed)
{
    bytes_from_polynomialvector(r.first<KYBER_POLYVECBYTES>(), pk);
    auto seed_dest = r.subspan<KYBER_POLYVECBYTES, KYBER_SYMBYTES>();
    std::copy(seed.begin(), seed.end(), seed_dest.begin());
}

static void unpack_pk(std::span<int16_t, KYBER_K * KYBER_N> pk,
                      std::span<uint8_t, KYBER_SYMBYTES> seed,
                      std::span<const uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> packedpk)
{
    polynomialvector_from_bytes(pk, packedpk.first<KYBER_POLYVECBYTES>());
    auto seed_src = packedpk.subspan<KYBER_POLYVECBYTES, KYBER_SYMBYTES>();
    std::copy(seed_src.begin(), seed_src.end(), seed.begin());
}

static void pack_sk(std::span<uint8_t, KYBER_INDCPA_SECRETKEYBYTES> r,
                    std::span<const int16_t, KYBER_K * KYBER_N> sk)
{
    bytes_from_polynomialvector(r, sk);
}

static void unpack_sk(std::span<int16_t, KYBER_K * KYBER_N> sk,
                      std::span<const uint8_t, KYBER_INDCPA_SECRETKEYBYTES> packedsk)
{
    polynomialvector_from_bytes(sk, packedsk);
}

static void pack_ciphertext(std::span<uint8_t, KYBER_INDCPA_BYTES> r,
                            std::span<const int16_t, KYBER_K * KYBER_N> b,
                            std::span<const int16_t, KYBER_N> v)
{
    compress(r.first<KYBER_POLYVECCOMPRESSEDBYTES>(), b);
    compress(r.subspan<KYBER_POLYVECCOMPRESSEDBYTES>(), v);
}

static void unpack_ciphertext(std::span<int16_t, KYBER_K * KYBER_N> b,
                              std::span<int16_t, KYBER_N> v,
                              std::span<const uint8_t, KYBER_INDCPA_BYTES> c)
{
    polyvec_decompress(b, c.first<KYBER_POLYVECCOMPRESSEDBYTES>());
    decompress(v, c.subspan<KYBER_POLYVECCOMPRESSEDBYTES>());
}
static unsigned int rej_uniform(std::span<int16_t> r, std::span<const uint8_t> buf) {
    unsigned int ctr = 0;
    unsigned int pos = 0;
    uint16_t val0, val1;

    while (ctr < r.size() && pos + 3 <= buf.size()) {
        val0 = ((buf[pos + 0] >> 0) | (static_cast<uint16_t>(buf[pos + 1]) << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | (static_cast<uint16_t>(buf[pos + 2]) << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q)
            r[ctr++] = val0;
        if (ctr < r.size() && val1 < KYBER_Q)
            r[ctr++] = val1;
    }

    return ctr;
}

static_assert(XOF_BLOCKBYTES % 3 == 0, "Implementation of gen_matrix assumes that XOF_BLOCKBYTES is a multiple of 3");

constexpr size_t GEN_MATRIX_NBLOCKS = ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES);

inline void generate_random_matrix(
    std::span<int16_t, KYBER_K * KYBER_K * KYBER_N> A, 
    std::span<const uint8_t, KYBER_SYMBYTES> seed, 
    bool transposed
){
    std::array<uint8_t, GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES> buf;
    xof_state state;

    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_K; j++) {
            if (transposed) {
                xof_absorb(&state, seed, i, j);
            } else {
                xof_absorb(&state, seed, j, i);
            }

            xof_squeezeblocks(buf.data(), GEN_MATRIX_NBLOCKS, &state);
            
            auto poly_coeffs = A.subspan((i * KYBER_K + j) * KYBER_N, KYBER_N);
            size_t ctr = rej_uniform(poly_coeffs, buf);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf.data(), 1, &state);
                
                ctr += rej_uniform(
                    poly_coeffs.subspan(ctr), 
                    std::span{buf}.first(XOF_BLOCKBYTES)
                );
            }
        }
    }
}


inline void keygeneration_pk_sk(
    std::span<uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> public_key,
    std::span<uint8_t, KYBER_INDCPA_SECRETKEYBYTES> secret_key,
    std::span<const uint8_t, KYBER_SYMBYTES> seed
)
{
    std::array<uint8_t, 2 * KYBER_SYMBYTES> hash;
    sha3_512(hash, seed);

    auto public_seed  = std::span(hash).first<KYBER_SYMBYTES>();
    auto noise_seed   = std::span(hash).last<KYBER_SYMBYTES>();

    
    uint8_t nonce = 0;

    std::array<int16_t, KYBER_K * KYBER_K * KYBER_N> mat;
    std::array<int16_t, KYBER_K * KYBER_N> noise;
    std::array<int16_t, KYBER_K * KYBER_N> secret;
    generate_random_matrix(mat, public_seed, false);
    cbd_noise_polynomialvector_eta1(secret, noise_seed, nonce);
    cbd_noise_polynomialvector_eta1(noise, noise_seed, nonce + KYBER_K);
    
    polynomialvector_ntt(secret);
    polynomialvector_ntt(noise);
    
    std::array<int16_t, KYBER_K * KYBER_N> buffer;
    std::span<int16_t, KYBER_K * KYBER_N> public_key_polynomialvector(buffer);

    for (size_t i = 0; i < KYBER_K; i++) {
        polynomialvector_dotproduct(range(public_key_polynomialvector, i), range(mat, i), secret);
        montogomery_domain(range(public_key_polynomialvector, i));
    }

    polynomialvector_addition(buffer, buffer, noise);
    reduce(buffer);

    bytes_from_polynomialvector(secret_key, secret);
    pack_pk(public_key, buffer, public_seed);
}


// u = A^T * r + e1 , v = t^T * r + e2 + m * (q/2)

inline void kyber_enc(std::span<uint8_t, KYBER_INDCPA_BYTES> ciphertext,
                std::span<const uint8_t, KYBER_INDCPA_MSGBYTES> message,
                std::span<const uint8_t, KYBER_INDCPA_PUBLICKEYBYTES> public_key,
                std::span<const uint8_t, KYBER_SYMBYTES> seed)
{
    std::array<uint8_t, KYBER_SYMBYTES> tmp_seed;
    uint8_t nonce = 0;
    
    std::array<int16_t, KYBER_K * KYBER_N> r;
    std::array<int16_t, KYBER_K * KYBER_N> t;
    std::array<int16_t, KYBER_K * KYBER_N> e1;
    std::array<int16_t, KYBER_K * KYBER_K * KYBER_N> at; // A^T
    std::array<int16_t, KYBER_K * KYBER_N> u;
    
    std::array<int16_t, KYBER_N> v;
    std::array<int16_t, KYBER_N> m_q2;
    std::array<int16_t, KYBER_N> e2;

    unpack_pk(t, tmp_seed, public_key);
    polynomial_from_message(m_q2, message);
    generate_random_matrix(at, tmp_seed, true);

    cbd_noise_polynomialvector_eta1(r, seed, nonce);
    cbd_noise_polynomialvector_eta2(e1, seed, nonce + KYBER_K);
    
    cbd_noise_polynomial_eta2(e2, seed, nonce++);

    polynomialvector_ntt(r);

    for (size_t i = 0; i < KYBER_K; i++)
        polynomialvector_dotproduct(range(u, i), range(at, i), r);

    polynomialvector_dotproduct(v, t, r);

    polynomialvector_intt(u);
    polynomial_intt(v);

    polynomialvector_addition(u, u, e1);
    polynomial_addition(v, v, e2);
    polynomial_addition(v, v, m_q2);
    
    reduce(u);
    reduce(v);

    pack_ciphertext(ciphertext, u, v);
}


// m' = v - s^T * u
// m = recover_message(m')

inline void kyber_dec(std::span<uint8_t, KYBER_INDCPA_MSGBYTES> decrypted_message,
                std::span<const uint8_t, KYBER_INDCPA_BYTES> ciphertext,
                std::span<const uint8_t, KYBER_INDCPA_SECRETKEYBYTES> secret_key)
{
    std::array<int16_t, KYBER_K * KYBER_N> u;
    std::array<int16_t, KYBER_K * KYBER_N> s;
    
    std::array<int16_t, KYBER_N> v;
    std::array<int16_t, KYBER_N> m_prime;

    unpack_ciphertext(u, v, ciphertext);
    unpack_sk(s, secret_key);

    polynomialvector_ntt(u);
    
    polynomialvector_dotproduct(m_prime, s, u);
    polynomial_intt(m_prime);

    polynomial_subtraction(m_prime, v, m_prime);
    reduce(m_prime);

    message_from_polynomial(decrypted_message, m_prime);
}