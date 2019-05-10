#include "polynomials.h"

uint64_t modexp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent = (exponent >> 1);
    }
    return result;
}

vector<uint64_t> polynomial_from_roots(vector<uint64_t> &roots, uint64_t modulus) {
    vector<uint64_t> result(roots.size() + 1, 0);
    result[0] = 1;

    for (size_t i = 0; i < roots.size(); i++) {
        // multiply result by (x - root)
        uint64_t neg_root = modulus - (roots[i] % modulus);

        for (size_t j = i + 1; j > 0; j--) {
            result[j] = (result[j - 1] + neg_root * result[j]) % modulus;
        }
        result[0] = (result[0] * neg_root) % modulus;
    }

    return result;
}
