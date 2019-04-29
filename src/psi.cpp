#include "seal/seal.h"

#include "psi.h"
#include "polynomials.cpp"

#define DEBUG

#ifdef DEBUG
// this code will only be compiled in debug mode.
#include <iostream>
// we save the receiver's key in a global variable, because it is helpful to
// have access to it when debugging sender code.
SecretKey *receiver_key_leaked;
#endif

PSIReceiver::PSIReceiver(shared_ptr<SEALContext> context, size_t input_bits)
    : context(context),
      input_bits(input_bits),
      keygen(context),
      public_key_(keygen.public_key()),
      secret_key(keygen.secret_key())
{
#ifdef DEBUG
    receiver_key_leaked = &secret_key;
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

        int64_t decrypted_value;
        try {
            decrypted_value = encoder.decode_int64(decrypted);
        } catch (invalid_argument) {
            // the decrypted value is too big to fit into an int64, so it's
            // definitely not zero.
            continue;
        }

        if (decrypted_value == 0) {
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

    // compute the coefficients of the polynomial f(x) = \prod_i (x - inputs[i])
    vector<int> f_coeffs = polynomial_from_roots(inputs);
    vector<Plaintext> f_coeffs_enc(f_coeffs.size());
    for (size_t i = 0; i < f_coeffs.size(); i++) {
        encoder.encode(f_coeffs[i], f_coeffs_enc[i]);
    }

    vector<Ciphertext> powers(f_coeffs.size());
    encryptor.encrypt(encoder.encode(1), powers[0]);

    Ciphertext zero;
    encryptor.encrypt(encoder.encode(0), zero);

    for (size_t i = 0; i < receiver_inputs.size(); i++) {
        // first, compute all the powers of the receiver's input
        powers[1] = receiver_inputs[i];
        for (size_t j = 2; j < powers.size(); j++) {
            if (j & 2 == 0) {
                evaluator.square(powers[j >> 1], powers[j]);
            } else {
                evaluator.multiply(powers[j - 1], powers[1], powers[j]);
            }
        }

        // now use the computed powers to evaluate f(input)
        result[i] = zero;

#ifdef DEBUG
        Decryptor decryptor(context, *receiver_key_leaked);
        cerr << "computing matches for receiver input #" << i << endl;
        cerr << "initially the noise budget is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif

        for (size_t j = 0; j < f_coeffs.size(); j++) {
            // term = receiver_inputs[i]^j * f_coeffs[j]
            Ciphertext term;
            if (f_coeffs[j] != 0) {
                // multiply_plain does not allow the second parameter to be zero.
                evaluator.multiply_plain(powers[j], f_coeffs_enc[j], term);
                evaluator.add_inplace(result[i], term);
            }

#ifdef DEBUG
        cerr << "after term " << j << " it is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif
        }

        // now multiply the result of the computation by a random mask
        int random_mask = random->generate() & ((1 << input_bits) - 1);
        evaluator.multiply_plain_inplace(result[i], encoder.encode(random_mask));
    }

    return result;
}
