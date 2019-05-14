#include <vector>

#include "random.h"

void generate_random_sender_set(shared_ptr<UniformRandomGenerator> random,
                                vector<uint64_t> &inputs,
                                size_t bits);

void generate_random_labels(shared_ptr<UniformRandomGenerator> random,
                            vector<uint64_t> &labels,
                            size_t bits);

void generate_random_receiver_set(shared_ptr<UniformRandomGenerator> random,
                                  vector<uint64_t> &inputs,
                                  vector<uint64_t> &sender_inputs,
                                  size_t bits,
                                  uint64_t match_prob_percent);
