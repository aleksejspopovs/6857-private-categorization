#pragma once
#include <cstdint>

#include "seal/seal.h"

using namespace seal;
using namespace std;

/* This helper function uses a UniformRandomGenerator (which outputs 32-bit
   values) to uniformly pick an n-bit value, where n can be up to 64. */
uint64_t random_bits(shared_ptr<UniformRandomGenerator> random, size_t bits);

/* This helper function uniformly picks an integer x with 0 <= x < limit. */
uint64_t random_integer(shared_ptr<UniformRandomGenerator> random, uint64_t limit);

/* This helper function uniformly picks an integer x with 0 < x < limit. */
uint64_t random_nonzero_integer(shared_ptr<UniformRandomGenerator> random, uint64_t limit);
