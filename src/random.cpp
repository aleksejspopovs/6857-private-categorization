#include <cassert>

#include "random.h"

uint64_t random_bits(shared_ptr<UniformRandomGenerator> random, size_t bits) {
    assert(bits <= 64);
    // generate 64 bits of randomness
    uint64_t result = (random->generate() | ((uint64_t) random->generate() << 32));
    // reduce that to k bits of randomness;
    result = (result >> (64 - bits));
    return result;
}

uint64_t random_integer(shared_ptr<UniformRandomGenerator> random, uint64_t limit) {
    /* here's the trick: suppose 2^k < modulus <= 2^{k+1}. then we draw a random
       number x between 0 and 2^{k+1}. if it's less than modulus, we return it,
       otherwise we draw again (so the probability of success is at least 1/2). */
    uint64_t k = 0;
    while (limit > (1ULL << k)) {
        k++;
    }

    uint64_t result;
    do {
        result = random_bits(random, k);
    } while (result >= limit);

    return result;
}

uint64_t random_nonzero_integer(shared_ptr<UniformRandomGenerator> random, uint64_t limit) {
    uint64_t result;
    do {
        result = random_integer(random, limit);
    } while (result == 0);

    return result;
}
