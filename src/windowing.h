#pragma once

#include <cstdint>
#include <vector>

#include "seal/seal.h"

using namespace std;
using namespace seal;

/*
Windowing is a kind of optimization that is used when party A needs to send some
value y over to party B, and then party B needs to compute all powers
(y, y^2, y^3, ... y^m), but multiplications are more expensive for B than for A.

The basic idea is that A can compute some, but not all powers of y, choosing
them strategically to minimize the number of multiplications that B will have
to perform.

This class implements a windowing optimization described in [CLR17] that is
parametrized over a window size l and maximum power m, and requires A to send
over the values y^{2^{l * i} * j} for each 0 <= i <= ceil(log2(m) / l) and
1 <= j <= 2^l - 1.

Additionally, we implement the special case l = 0 that does not use windowing
and only sends over y.
*/

class Windowing
{
public:
    Windowing(size_t window_size, size_t max_power);
    /* NB: prepare will overwrite the input. */
    void prepare(vector<uint64_t> &input,
                 vector<Ciphertext> &windows,
                 uint64_t modulus,
                 BatchEncoder &encoder,
                 Encryptor &encryptor);
    /* NB: compute_powers leaves powers[0] untouched. */
    void compute_powers(vector<Ciphertext> &windows,
                        vector<Ciphertext> &powers,
                        Evaluator &evaluator,
                        RelinKeys &relin_keys);

private:
    size_t window_size;
    size_t max_power;
    size_t window_width;
    size_t window_count;
};
