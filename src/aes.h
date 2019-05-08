/* This implementation is based on the public domain hardware-accelerated AES
   in Peter Rindal's cryptoTools:
   https://github.com/ladnir/cryptoTools/blob/master/cryptoTools/Crypto/AES.h */
#pragma once
#include <cstdint>
#include <utility>

#include <wmmintrin.h>

using namespace std;

class AES
{
public:
        AES();
        void set_key(uint64_t key_high, uint64_t key_low);
        pair<uint64_t, uint64_t> encrypt(uint64_t block_high, uint64_t block_low);

private:
        __m128i round_key[11];
};
