#include <cassert>
#include <iostream>

#include "psi.h"
#include "random.h"

using namespace std;

int main()
{
    auto random_factory = UniformRandomGeneratorFactory::default_factory();
    auto random = random_factory->create();

    size_t receiver_N = 100;
    size_t sender_N = 1024; //1ull << 20;
    size_t input_bits = 8;
    size_t poly_modulus_degree = 8192;

    vector<uint64_t> sender_inputs(sender_N);
    vector<uint64_t> sender_labels(sender_N);
    for (size_t i = 0; i < sender_N; i++) {
        sender_inputs[i] = random_bits(random, input_bits);
        sender_labels[i] = random_bits(random, 2);
    }

    vector<uint64_t> receiver_inputs(receiver_N);
    for (size_t i = 0; i < receiver_N; i++) {
        if (random_integer(random, 100) < 70) {
            receiver_inputs[i] = sender_inputs[random_integer(random, sender_N)];
        } else {
            receiver_inputs[i] = random_bits(random, input_bits);
        }
    }

    // step 1: agreeing on parameters.
    PSIParams params(receiver_inputs.size(), sender_inputs.size(), input_bits, poly_modulus_degree);
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
    for (uint64_t x : receiver_inputs) {
        cout << x << " ";
    }
    cout << endl;

    vector<bucket_slot> receiver_buckets;
    auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs, receiver_buckets);

    // cout << "User's buckets: ";
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
    optional<vector<uint64_t>> labels = sender_labels;
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
    auto receiver_matches = user.decrypt_labeled_matches(sender_matches);

    cout << receiver_matches.size() << " matches found: ";
    for (auto i : receiver_matches) {
        assert(i.first < receiver_buckets.size());
        assert(receiver_buckets[i.first] != BUCKET_EMPTY);
        cout << receiver_inputs[receiver_buckets[i.first].first] << "-" << i.second << " ";
    }
    cout << endl;

    return 0;
}
