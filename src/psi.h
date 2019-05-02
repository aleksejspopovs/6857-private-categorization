#include "seal/seal.h"

using namespace std;
using namespace seal;

class PSIReceiver
{
public:
    PSIReceiver(shared_ptr<SEALContext> context, size_t input_bits);
    vector<Ciphertext> encrypt_inputs(vector<uint64_t> &inputs);
    vector<size_t> decrypt_matches(vector<Ciphertext> &encrypted_matches);
    PublicKey& public_key();
    RelinKeys relin_keys();

private:
    shared_ptr<SEALContext> context;
    size_t input_bits;
    KeyGenerator keygen;
    PublicKey public_key_;
    SecretKey secret_key;
};

class PSISender
{
public:
    PSISender(shared_ptr<SEALContext> context, size_t input_bits);
    vector<Ciphertext> compute_matches(vector<uint64_t> &inputs,
                                       PublicKey& receiver_public_key,
                                       RelinKeys relin_keys,
                                       vector<Ciphertext> &receiver_inputs);

private:
    shared_ptr<SEALContext> context;
    size_t input_bits;
};
