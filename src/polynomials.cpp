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

void polynomial_from_roots(vector<uint64_t> &roots, vector<uint64_t> &coeffs, uint64_t modulus) {
    coeffs.clear();
    coeffs.resize(roots.size() + 1);
    coeffs[0] = 1;

    for (size_t i = 0; i < roots.size(); i++) {
        // multiply coeffs by (x - root)
        uint64_t neg_root = modulus - (roots[i] % modulus);

        for (size_t j = i + 1; j > 0; j--) {
            coeffs[j] = (coeffs[j - 1] + neg_root * coeffs[j]) % modulus;
        }
        coeffs[0] = (coeffs[0] * neg_root) % modulus;
    }
}
