#include <chrono>
#include <iostream>
#include <set>
#include <vector>

#include "psi.h"
#include "random.h"

using namespace std;
using namespace seal;

int main(int argc, char** argv)
{
    if (argc != 9) {
        cout << "USAGE:" << endl;
        cout << argv[0] << " labeled" // argv[1]
                        << " inputs_bits" // argv[2]
                        << " sender_size" // argv[3]
                        << " receiver_size" // argv[4]
                        << " poly_modulus_degree" // argv[5]
                        << " partition_count" // argv[6]
                        << " window_size" // argv[7]
                        << " iteration_count" // argv[8]
                        << endl;
        return 1;
    }

    bool labeled = (atol(argv[1]) != 0);
    size_t input_bits = atol(argv[2]);
    size_t sender_size = atol(argv[3]);
    size_t receiver_size = atol(argv[4]);
    size_t poly_modulus_degree = atol(argv[5]);
    size_t partition_count = atol(argv[6]);
    size_t window_size = atol(argv[7]);
    size_t iteration_count = atol(argv[8]);

    auto random_factory = UniformRandomGeneratorFactory::default_factory();
    auto random = random_factory->create();

    vector<uint64_t> sender_inputs(sender_size);
    vector<uint64_t> sender_labels(sender_size);
    vector<uint64_t> receiver_inputs(receiver_size);
    set<uint64_t> receiver_seen;
    set<uint64_t> sender_seen;

    for (size_t i = 0; i < iteration_count; i++) {
        // generate random inputs
        sender_seen.clear();
        for (size_t j = 0; j < sender_size; j++) {
            uint64_t value;
            do {
                value = random_bits(random, input_bits);
            } while (sender_seen.count(value) > 0);
            sender_inputs[j] = value;
            sender_seen.insert(value);
        }
        if (labeled) {
            for (size_t j = 0; j < sender_size; j++) {
                sender_labels[j] = random_bits(random, input_bits);
            }
        }

        receiver_seen.clear();
        for (size_t j = 0; j < receiver_size; j++) {
            uint64_t value;
            do {
                value = (random_bits(random, 1) == 0)
                        ? random_bits(random, input_bits)
                        : sender_inputs[random_integer(random, sender_size)];
            } while (receiver_seen.count(value) > 0);
            receiver_inputs[j] = value;
            receiver_seen.insert(value);
        }

        // generate params
        PSIParams params(receiver_size, sender_size, input_bits, poly_modulus_degree);
        params.set_sender_partition_count(partition_count);
        params.set_window_size(window_size);
        params.generate_seeds();

        // do the actual benchmarking
        // phase 1: receiver encoding
        auto receiver_enc_start = chrono::system_clock::now();

        PSIReceiver user(params);
        vector<bucket_slot> receiver_buckets;
        auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs, receiver_buckets);

        auto receiver_enc_end = chrono::system_clock::now();
        chrono::duration<double> receiver_enc_duration = receiver_enc_end - receiver_enc_start;

        // phase 2: sender
        auto sender_start = chrono::system_clock::now();

        PSISender server(params);
        optional<vector<uint64_t>> labels;
        if (labeled) {
            labels = sender_labels;
        }
        auto sender_matches = server.compute_matches(
            sender_inputs,
            labels,
            user.public_key(),
            user.relin_keys(),
            receiver_encrypted_inputs
        );

        auto sender_end = chrono::system_clock::now();
        chrono::duration<double> sender_duration = sender_end - sender_start;

        // phase 3: receiver decoding
        auto receiver_dec_start = chrono::system_clock::now();

        vector<size_t> matches;
        vector<pair<size_t, uint64_t>> labeled_matches;
        size_t match_count;

        if (labeled) {
            labeled_matches = user.decrypt_labeled_matches(sender_matches);
            match_count = labeled_matches.size();
        } else {
            matches = user.decrypt_matches(sender_matches);
            match_count = matches.size();
        }

        auto receiver_dec_end = chrono::system_clock::now();
        chrono::duration<double> receiver_dec_duration = receiver_dec_end - receiver_dec_start;

        // output the timings
        cout << sender_duration.count()
             << "\t" << receiver_enc_duration.count()
             << "\t" << receiver_dec_duration.count()
             << "\t" << match_count
             << endl;
    }

    return 0;
}
