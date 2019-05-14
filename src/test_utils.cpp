#include <set>

#include "test_utils.h"

void generate_random_sender_set(shared_ptr<UniformRandomGenerator> random,
                                vector<uint64_t> &inputs,
                                size_t bits)
{
    set<uint64_t> seen;
    for (size_t j = 0; j < inputs.size(); j++) {
        uint64_t value;
        do {
            value = random_bits(random, bits);
        } while (seen.count(value) > 0);
        inputs[j] = value;
        seen.insert(value);
    }
}

void generate_random_labels(shared_ptr<UniformRandomGenerator> random,
                            vector<uint64_t> &labels,
                            size_t bits)
{
    for (size_t j = 0; j < labels.size(); j++) {
        labels[j] = random_bits(random, bits);
    }
}

void generate_random_receiver_set(shared_ptr<UniformRandomGenerator> random,
                                  vector<uint64_t> &inputs,
                                  vector<uint64_t> &sender_inputs,
                                  size_t bits,
                                  uint64_t match_prob_percent)
{
    set<uint64_t> seen;
    size_t matches = (inputs.size() * match_prob_percent) / 100;
    for (size_t j = 0; j < inputs.size(); j++) {
        uint64_t value;
        do {
            value = (j < matches)
                    ? sender_inputs[random_integer(random, sender_inputs.size())]
                    : random_bits(random, bits);
        } while (seen.count(value) > 0);
        inputs[j] = value;
        seen.insert(value);
    }
    // shuffle to make sure the matches aren't all in the beginning
    for (size_t j = 1; j < inputs.size(); j++) {
        size_t k = random_integer(random, j + 1);
        swap(inputs[j], inputs[k]);
    }
}
