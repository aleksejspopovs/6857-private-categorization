#include <cassert>

#include "polynomials.h"

#include "windowing.h"

// TODO:
// - figure out if there are any off-by-one errors that cause us to output more
//   powers than necessary
// - figure out if it's worth outputting fewer powers in the last window
// - optimize the early exits in compute_powers

Windowing::Windowing(size_t window_size, size_t max_power)
    : window_size(window_size), max_power(max_power)
{
    if (window_size > 0) {
        // TODO: evaluate if the performance benefit of adding one extra element
        // to each window (and using bit shifts to index into arrays) is worth
        // the memory/communication overhead.
        window_width = (1ull << window_size) - 1;
        window_count = 1;
        // `window_count` is the first `i` such that
        // `i > floor(log2(max_power + 1) / window_size)`
        while ((1ull << (window_count * window_size)) <= max_power) {
            window_count++;
        }
    }
}

void Windowing::prepare(vector<uint64_t> &input,
                        vector<Ciphertext> &windows,
                        uint64_t modulus,
                        BatchEncoder &encoder,
                        Encryptor &encryptor)
{
    Plaintext encoded;

    if (window_size == 0) {
        windows.resize(1);
        encoder.encode(input, encoded);
        encryptor.encrypt(encoded, windows[0]);
        return;
    }

    windows.resize(window_width * window_count);

    vector<uint64_t> input_mul;
    for (size_t i = 0; i < window_count; i++) {
        // throughout this loop, we maintain the following invariant
        // (where y denotes the initial input):
        // input = y^{2^{l * i}}
        // input_mul = y^{2^{l * i} * j}
        input_mul = input;
        for (size_t j = 1; j <= window_width; j++) {
            encoder.encode(input_mul, encoded);
            encryptor.encrypt(
                encoded,
                windows[i * window_width + j - 1]
            );

            if (j <= window_width - 1) {
                // multiply input_mul by input for next iteration.
                for (size_t k = 0; k < input.size(); k++) {
                    input_mul[k] = MUL_MOD(input_mul[k], input[k], modulus);
                }
            }
        }

        if (i < window_count - 1) {
            // take input to the 2^l power for next iteration.
            for (size_t k = 0; k < input.size(); k++) {
                input[k] = modexp(input[k], 1ull << window_size, modulus);
            }
        }
    }
}

void Windowing::compute_powers(vector<Ciphertext> &windows,
                               vector<Ciphertext> &powers,
                               Evaluator &evaluator,
                               RelinKeys &relin_keys)
{
    if (window_size == 0) {
        assert(windows.size() == 1);
        powers[1] = windows[0];
        for (size_t i = 2; i < powers.size(); i++) {
            if (i & 2 == 0) {
                evaluator.square(powers[i >> 1], powers[i]);
            } else {
                evaluator.multiply(powers[i - 1], powers[1], powers[i]);
            }
            evaluator.relinearize_inplace(powers[i], relin_keys);
        }
    } else {
        assert(windows.size() == window_width * window_count);
        // the first 2^l - 1 powers are directly copied over
        for (size_t i = 1; i <= window_width; i++) {
            if (i >= powers.size()) {
                return;
            }
            powers[i] = windows[i - 1];
        }

        for (size_t i = 1; i < window_count; i++) {
            for (size_t j = 1; j <= window_size; j++) {
                // now, for each new window i, we go over all of its elements
                // j (encoding y^{2^{l * i} * j}) and compute every power of the
                // form y^{2^{l * i} * j + k}, where k < 2^{l * i} (equivalently,
                // y^k was computed before we started working on window i).
                size_t high_bits = (j << (window_size * i));
                if (high_bits >= powers.size()) {
                    break;
                }
                powers[high_bits] = windows[i * window_width + j - 1];
                for (size_t low_bits = 1; low_bits < (1ull << (window_size * i)); low_bits++) {
                    size_t new_power = high_bits | low_bits;
                    if (new_power >= powers.size()) {
                        // TODO: figure out if there's a smarter way to break here.
                        break;
                    }
                    evaluator.multiply(powers[low_bits], powers[high_bits], powers[new_power]);
                    evaluator.relinearize_inplace(powers[new_power], relin_keys);
                }
            }
        }
    }
}
