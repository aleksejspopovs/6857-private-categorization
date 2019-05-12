#include <cassert>
#include <set>

#include "polynomials.h"

// if p is at most 32 bits, arithmetic modulo p can be implemented by directly
// using 64-bit arithmetic and reducing mod p. but if it's bigger,
// multiplication will overflow, so we have to use a slower multiplication
// algorithm.
#ifdef MODULUS_IS_SMALL
    #define MUL_MOD(a, b, m) (((a)*(b)) % (m))
#else
    // using __uint128_t, which is a GCC-specific extension
    #define MUL_MOD(a, b, m) ((((__uint128_t) (a)) * ((__uint128_t) (b))) % (m))
#endif


uint64_t modexp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    while (exponent > 0) {
        if (exponent & 1) {
            result = MUL_MOD(result, base, modulus);
        }
        base = MUL_MOD(base, base, modulus);
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
            coeffs[j] = (coeffs[j - 1] + MUL_MOD(neg_root, coeffs[j], modulus)) % modulus;
        }
        coeffs[0] = MUL_MOD(coeffs[0], neg_root, modulus);
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

    // first, get rid of all duplicate entries
    size_t unique_points = 0;
    set<uint64_t> xs_seen;
    for (size_t i = 0; i < xs.size(); i++) {
        if (xs_seen.count(xs[i]) == 0) {
            xs_seen.insert(xs[i]);
            xs[unique_points] = xs[i];
            ys[unique_points] = ys[i];
            unique_points++;
        }
    }

    // at iteration i of the loop, basis contains the coefficients of the basis
    // polynomial (x - xs[0]) * (x - xs[1]) * ... * (x - xs[i - 1])
    vector<uint64_t> basis(xs.size());
    basis[0] = 1;

    // at iteration i of the loop, ddif[j] contains the divided difference
    // [ys[j], ys[j + 1], ..., ys[j + i]]. thus initially, when i = 0,
    // ddif[j] = [ys[j]] = ys[j]
    vector<uint64_t> ddif = ys;

    for (size_t i = 0; i < unique_points; i++) {
        for (size_t j = 0; j < i + 1; j++) {
            coeffs[j] = (coeffs[j] + MUL_MOD(ddif[0], basis[j], modulus)) % modulus;
        }

        if (i < unique_points - 1) {
            // update basis: multiply it by (x - xs[i])
            uint64_t neg_x = modulus - (xs[i] % modulus);

            for (size_t j = i + 1; j > 0; j--) {
                basis[j] = (basis[j - 1] + MUL_MOD(neg_x, basis[j], modulus)) % modulus;
            }
            basis[0] = MUL_MOD(basis[0], neg_x, modulus);

            // update ddif: compute length-(i + 1) divided differences
            for (size_t j = 0; j + i + 1 < unique_points + 1; j++) {
                // dd_{j,j+i+1} = (dd_{j+1, j+i+1} - dd_{j, j+i}) / (x_{j+i+1} - x_j)
                uint64_t num = (ddif[j + 1] - ddif[j] + modulus) % modulus;
                uint64_t den = (xs[j + i + 1] - xs[j] + modulus) % modulus;
                ddif[j] = MUL_MOD(num, modinv(den, modulus), modulus);
            }
        }
    }
}
