#include <cassert>
#include <iostream>

#include "psi.h"
#include "random.h"
#include "test_utils.h"

using namespace std;

int main()
{
    auto random_factory = UniformRandomGeneratorFactory::default_factory();
    auto random = random_factory->create();

    size_t receiver_N = 10;//5535;
    size_t sender_N = 100; //1ull << 24;
    size_t input_bits = 32;
    size_t poly_modulus_degree = 8192;
    size_t partition_count = 2;//256;
    size_t window_size = 1;
    bool labeled = false;

    vector<uint64_t> sender_inputs(sender_N);
    vector<uint64_t> sender_labels(sender_N);
    vector<uint64_t> receiver_inputs(receiver_N);

    generate_random_sender_set(random, sender_inputs, input_bits);
    if (labeled) {
        generate_random_labels(random, sender_labels, input_bits);
    }
    generate_random_receiver_set(random, receiver_inputs, sender_inputs, input_bits, 50);

    // step 1: agreeing on parameters.
    PSIParams params(receiver_inputs.size(), sender_inputs.size(), input_bits, poly_modulus_degree);
    params.set_sender_partition_count(partition_count);
    params.set_window_size(window_size);
    params.generate_seeds();

    cout << "Parameters chosen:" << endl;
    cout << "  - sender set size: " << params.sender_size << endl;
    cout << "  - receiver set size: " << params.receiver_size << endl;
    cout << "  - element bit length: " << params.input_bits << endl;
    cout << "  - # of hash functions: " << params.hash_functions() << endl;
    cout << "  - hash seeds: ";
    for (auto seed : params.seeds) cout << seed << " ";
    cout << endl;
    cout << "  - log(bucket count), bucket_count: "
         << params.bucket_count_log() << " " << (1ull << params.bucket_count_log()) << endl;
    cout << "  - sender bucket capacity: " << params.sender_bucket_capacity() << endl;
    cout << endl;

    // all integers are going to be printed as hex now
    cout << hex;

    // step 2: receiver generates keys and inputs with the keys
    PSIReceiver user(params);
    cout << "User's set: ";
    // for (uint64_t x : receiver_inputs) {
    //     cout << x << " ";
    // }
    cout << endl;

    vector<bucket_slot> receiver_buckets;
    auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs, receiver_buckets);

    cout << "User's buckets: ";
    // for (auto x : receiver_buckets) {
    //     if (x == BUCKET_EMPTY) {
    //         cout << "--:-- ";
    //     } else {
    //         cout << x.first << ":" << receiver_inputs[x.first] << " ";
    //     }
    // }
    // cout << endl;
    cout << endl;


    // step 3: the sender evaluates polynomials
    // (after having received the receiver's public key and encrypted inputs)
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

    cout << "Sender's set: ";
    // for (size_t i = 0; i < sender_inputs.size(); i++) {
    //     cout << sender_inputs[i] << "-" << sender_labels[i] << " ";
    // }
    cout << endl;
    cout << endl;

    // step 4: the receiver decrypts the matches
    // (after having received the encrypted matches)
    if (labeled) {
        vector<pair<size_t, uint64_t>> receiver_labeled_matches;
        receiver_labeled_matches = user.decrypt_labeled_matches(sender_matches);
        cout << receiver_labeled_matches.size() << " matches found: ";
        // for (auto i : receiver_matches) {
        //     assert(i.first < receiver_buckets.size());
        //     assert(receiver_buckets[i.first] != BUCKET_EMPTY);
        //     cout << receiver_inputs[receiver_buckets[i.first].first] << "-" << i.second << " ";
        // }
    } else {
        vector<size_t> receiver_matches;
        receiver_matches = user.decrypt_matches(sender_matches);
        cout << receiver_matches.size() << " matches found: ";
        // for (auto i : receiver_matches) {
        //     assert(i < receiver_buckets.size());
        //     assert(receiver_buckets[i] != BUCKET_EMPTY);
        //     cout << receiver_inputs[receiver_buckets[i].first] << " ";
        // }
    }

    cout << endl;

    return 0;
}
