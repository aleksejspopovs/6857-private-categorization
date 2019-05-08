#include "aes.h"

__m128i key_gen_helper(__m128i key, __m128i key_rcon)
{
    key_rcon = _mm_shuffle_epi32(key_rcon, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, key_rcon);
}

AES::AES() {}

void AES::set_key(uint64_t key_high, uint64_t key_low)
{
    round_key[0] = _mm_set_epi64x(key_high, key_low);
    round_key[1] = key_gen_helper(round_key[0], _mm_aeskeygenassist_si128(round_key[0], 0x01));
    round_key[2] = key_gen_helper(round_key[1], _mm_aeskeygenassist_si128(round_key[1], 0x02));
    round_key[3] = key_gen_helper(round_key[2], _mm_aeskeygenassist_si128(round_key[2], 0x04));
    round_key[4] = key_gen_helper(round_key[3], _mm_aeskeygenassist_si128(round_key[3], 0x08));
    round_key[5] = key_gen_helper(round_key[4], _mm_aeskeygenassist_si128(round_key[4], 0x10));
    round_key[6] = key_gen_helper(round_key[5], _mm_aeskeygenassist_si128(round_key[5], 0x20));
    round_key[7] = key_gen_helper(round_key[6], _mm_aeskeygenassist_si128(round_key[6], 0x40));
    round_key[8] = key_gen_helper(round_key[7], _mm_aeskeygenassist_si128(round_key[7], 0x80));
    round_key[9] = key_gen_helper(round_key[8], _mm_aeskeygenassist_si128(round_key[8], 0x1B));
    round_key[10] = key_gen_helper(round_key[9], _mm_aeskeygenassist_si128(round_key[9], 0x36));
}

pair<uint64_t, uint64_t> AES::encrypt(uint64_t block_high, uint64_t block_low)
{
    __m128i ciphertext = _mm_set_epi64x(block_high, block_low);
    ciphertext = _mm_xor_si128(ciphertext, round_key[0]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[1]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[2]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[3]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[4]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[5]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[6]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[7]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[8]);
    ciphertext = _mm_aesenc_si128(ciphertext, round_key[9]);
    ciphertext = _mm_aesenclast_si128(ciphertext, round_key[10]);

    uint64_t result[2];
    _mm_storeu_si128((__m128i*) &result[0], ciphertext);

    return make_pair(result[1], result[0]);
}
