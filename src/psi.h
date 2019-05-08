#pragma once
#include "seal/seal.h"

using namespace std;
using namespace seal;

class PSIParams
{
public:
    PSIParams(size_t receiver_size, size_t sender_size, size_t input_bits);
    size_t hash_functions();
    size_t bucket_count_log();
    size_t sender_bucket_capacity();
    // you *must* call either generate_seeds or set_seeds.
    void generate_seeds();
    void set_seeds(vector<uint64_t> &seeds_ext);

    size_t receiver_size;
    size_t sender_size;
    size_t input_bits;
    shared_ptr<SEALContext> context;
    vector<uint64_t> seeds;
};

class PSIReceiver
{
public:
    PSIReceiver(PSIParams &params);
    vector<Ciphertext> encrypt_inputs(vector<uint64_t> &inputs);
    vector<size_t> decrypt_matches(vector<Ciphertext> &encrypted_matches);
    PublicKey& public_key();
    RelinKeys relin_keys();

private:
    PSIParams &params;
    KeyGenerator keygen;
    PublicKey public_key_;
    SecretKey secret_key;
};

class PSISender
{
public:
    PSISender(PSIParams &params);
    vector<Ciphertext> compute_matches(vector<uint64_t> &inputs,
                                       PublicKey& receiver_public_key,
                                       RelinKeys relin_keys,
                                       vector<Ciphertext> &receiver_inputs);

private:
    PSIParams &params;
};
