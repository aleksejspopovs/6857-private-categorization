#include <cstdint>
#include <vector>

using namespace std;

/*
The functions in this file implement some operations on polynomials, interpreted
as vectors of coefficients.
*/

/* modexp(a, b, m) computes a^b mod m in O(log b) time. */
uint64_t modexp(uint64_t base, uint64_t exponent, uint64_t modulus);

/*
polynomial_from_roots(l) returns the coefficients of the polynomial
(x - l[0]) * (x - l[1]) * ...

time complexity: O(n²), where n is the size of l
*/
vector<uint64_t> polynomial_from_roots(vector<uint64_t> &roots, uint64_t modulus);
