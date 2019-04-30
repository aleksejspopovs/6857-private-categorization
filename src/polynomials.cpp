#include <vector>

using namespace std;

/*
The functions in this file implement some operations on polynomials, interpreted
as vectors of coefficients.
*/

/*
polynomial_from_roots(l) returns the coefficients of the polynomial
(x - l[0]) * (x - l[1]) * ...

time complexity: O(n²), where n is the size of l
*/
#include <iostream>
template <typename T>
std::vector<T> polynomial_from_roots(std::vector<T> &roots, T modulus) {
    std::vector<T> result(roots.size() + 1, 0);
    result[0] = 1;

    for (size_t i = 0; i < roots.size(); i++) {
        // multiply result by (x - root)
        T neg_root = modulus - (roots[i] % modulus);

        for (size_t j = i + 1; j > 0; j--) {
            result[j] = (result[j - 1] + neg_root * result[j]) % modulus;
        }
        result[0] = (result[0] * neg_root) % modulus;
    }

    return result;
}
