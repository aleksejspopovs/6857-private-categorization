#include "seal/seal.h"

#include "psi.h"

#define DEBUG

#ifdef DEBUG
// this code will only be compiled in debug mode.
#include <iostream>
// we save the receiver's key in a global variable, because it is helpful to
// have access to it when debugging sender code.
SecretKey receiver_key_leaked;
#endif

PSIReceiver::PSIReceiver(shared_ptr<SEALContext> context, size_t input_bits)
    : context(context),
      input_bits(input_bits),
      keygen(context),
      public_key_(keygen.public_key()),
      secret_key(keygen.secret_key())
{
#ifdef DEBUG
    receiver_key_leaked = secret_key;
#endif
}

vector<Ciphertext> PSIReceiver::encrypt_inputs(vector<int> &inputs)
{
    Encryptor encryptor(context, public_key_);
    IntegerEncoder encoder(context);
    vector<Ciphertext> result(inputs.size());

    for (size_t i = 0; i < inputs.size(); i++) {
        encryptor.encrypt(encoder.encode(inputs[i]), result[i]);
    }

    return result;
}

vector<size_t> PSIReceiver::decrypt_matches(vector<Ciphertext> &encrypted_matches)
{
    Decryptor decryptor(context, secret_key);
    IntegerEncoder encoder(context);
    vector<size_t> result;

    for (size_t i = 0; i < encrypted_matches.size(); i++) {
        Plaintext decrypted;
        decryptor.decrypt(encrypted_matches[i], decrypted);

        if (decrypted.is_zero()) {
            result.push_back(i);
        }
    }

    return result;
}

PublicKey& PSIReceiver::public_key()
{
    return public_key_;
}

PSISender::PSISender(shared_ptr<SEALContext> context, size_t input_bits)
    : context(context),
      input_bits(input_bits)
{
}

vector<Ciphertext> PSISender::compute_matches(vector<int> &inputs,
                                              PublicKey& receiver_public_key,
                                              vector<Ciphertext> &receiver_inputs)
{
    vector<Ciphertext> result(receiver_inputs.size());

    auto random_factory = UniformRandomGeneratorFactory::default_factory();
    auto random = random_factory->create();

    Encryptor encryptor(context, receiver_public_key);
    IntegerEncoder encoder(context);
    Evaluator evaluator(context);

    vector<Plaintext> encoded_inputs(inputs.size());
    for (size_t i = 0; i < inputs.size(); i++) {
        encoder.encode(inputs[i], encoded_inputs[i]);
    }

    for (size_t i = 0; i < receiver_inputs.size(); i++) {
        /* the result starts out with a random value, and is then multiplied
           by (receiver_inputs[i] - inputs[j]) for each j */
        int random_mask = random->generate() & ((1 << input_bits) - 1);
        encryptor.encrypt(encoder.encode(random_mask), result[i]);

#ifdef DEBUG
        Decryptor decryptor(context, receiver_key_leaked);
        cerr << "computing matches for receiver input #" << i << endl;
        cerr << "initially the noise budget is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif

        for (size_t j = 0; j < inputs.size(); j++) {
            // term = (receiver_inputs[i] - inputs[j])
            Ciphertext term;
            evaluator.sub_plain(receiver_inputs[i], encoded_inputs[j], term);
            evaluator.multiply_inplace(result[i], term);

#ifdef DEBUG
        cerr << "after match " << j << " it is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif
        }
    }

    return result;
}
