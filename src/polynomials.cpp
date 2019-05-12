#include <cassert>

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

uint64_t modinv(uint64_t x, uint64_t modulus) {
    return modexp(x, modulus - 2, modulus);
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

void polynomial_from_points(vector<uint64_t> &xs,
                            vector<uint64_t> &ys,
                            vector<uint64_t> &coeffs,
                            uint64_t modulus)
{
    assert(xs.size() == ys.size());
    coeffs.clear();
    coeffs.resize(xs.size());

    // at iteration i of the loop, basis contains the coefficients of the basis
    // polynomial (x - xs[0]) * (x - xs[1]) * ... * (x - xs[i - 1])
    vector<uint64_t> basis(xs.size());
    basis[0] = 1;

    // at iteration i of the loop, ddif[j] contains the divided difference
    // [ys[j], ys[j + 1], ..., ys[j + i]]. thus initially, when i = 0,
    // ddif[j] = [ys[j]] = ys[j]
    vector<uint64_t> ddif = ys;

    for (size_t i = 0; i < xs.size(); i++) {
        // result += ddif[0] * basis
        for (size_t j = 0; j < i + 1; j++) {
            coeffs[j] = (coeffs[j] + ddif[0] * basis[j]) % modulus;
        }

        if (i < xs.size() - 1) {
            // update basis: multiply it by (x - xs[i])
            uint64_t neg_x = modulus - (xs[i] % modulus);

            for (size_t j = i + 1; j > 0; j--) {
                basis[j] = (basis[j - 1] + neg_x * basis[j]) % modulus;
            }
            basis[0] = (basis[0] * neg_x) % modulus;

            // update ddif: compute length-(i + 1) divided differences
            for (size_t j = 0; j + i + 1 < xs.size() + 1; j++) {
                // dd_{j,j+i+1} = (dd_{j+1, j+i+1} - dd_{j, j+i}) / (x_{j+i+1} - x_j)
                uint64_t num = (ddif[j + 1] - ddif[j] + modulus) % modulus;
                uint64_t den = (xs[j + i + 1] - xs[j] + modulus) % modulus;
                ddif[j] = (num * modinv(den, modulus)) % modulus;
            }
        }
    }
}
