#include "seal/seal.h"

#include "psi.h"
#include "polynomials.cpp"
#include "random.h"

#define DEBUG

#ifdef DEBUG
// this code will only be compiled in debug mode.
#include <iostream>
// we save the receiver's key in a global variable, because it is helpful to
// have access to it when debugging sender code.
SecretKey *receiver_key_leaked;
#endif

/* This helper function uses a BatchEncoder to encode the vector
   [value, value, value, ..., value] into destination. */
void encode_const_vector(BatchEncoder &encoder, uint64_t value, Plaintext &destination)
{
    size_t slot_count = encoder.slot_count();
    destination.resize(slot_count);
    for (size_t i = 0; i < slot_count; i++) {
        destination[i] = value;
    }
    encoder.encode(destination);
}

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

vector<Ciphertext> PSIReceiver::encrypt_inputs(vector<uint64_t> &inputs)
{
    Encryptor encryptor(context, public_key_);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // each ciphertext will encode (at most) slot_count inputs, so we'll
    // need ceil(n / slot_count) ciphertexts.
    size_t ciphertext_count = (inputs.size() + (slot_count - 1)) / slot_count;
    vector<Ciphertext> result(ciphertext_count);

    Plaintext inputs_grouped(slot_count, slot_count);

    for (size_t i = 0; i < ciphertext_count; i++) {
        // figure out how many inputs we'll be putting into this ciphertext:
        // this is slot_count for all blocks except the last one
        size_t inputs_here = (i < ciphertext_count - 1)
                             ? slot_count
                             : (inputs.size() % slot_count);

        inputs_grouped.resize(inputs_here);
        for (size_t j = 0; j < inputs_here; j++) {
            // TODO: do we need to reduce by plain_modulus here?
            inputs_grouped[j] = inputs[slot_count * i + j];
        }

        // encode all of the inputs, in-place
        encoder.encode(inputs_grouped);

        encryptor.encrypt(inputs_grouped, result[i]);
    }

    return result;
}

vector<size_t> PSIReceiver::decrypt_matches(vector<Ciphertext> &encrypted_matches)
{
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    vector<size_t> result;

    for (size_t i = 0; i < encrypted_matches.size(); i++) {
        Plaintext decrypted;
        decryptor.decrypt(encrypted_matches[i], decrypted);

        // decode in-place
        encoder.decode(decrypted);

        for (size_t j = 0; j < slot_count; j++) {
            // TODO: if the number of inputs was not divisible by slot_count,
            // we'll get some extra zeroes at the end of the encoded inputs,
            // so we'll get some extra elements here. for now, assume 0 is not
            // in the sender's set, so the polynomial won't evaluate to 0 there.
            // (otherwise we might return out-of-bound indices here)
            if (decrypted[j] == 0) {
                result.push_back(slot_count * i + j);
            }
        }
    }

    return result;
}

PublicKey& PSIReceiver::public_key()
{
    return public_key_;
}

RelinKeys PSIReceiver::relin_keys()
{
    return keygen.relin_keys(5);
}

PSISender::PSISender(shared_ptr<SEALContext> context, size_t input_bits)
    : context(context),
      input_bits(input_bits)
{
}

vector<Ciphertext> PSISender::compute_matches(vector<uint64_t> &inputs,
                                              PublicKey& receiver_public_key,
                                              RelinKeys relin_keys,
                                              vector<Ciphertext> &receiver_inputs)
{
    vector<Ciphertext> result(receiver_inputs.size());

    auto random_factory = UniformRandomGeneratorFactory::default_factory();
    auto random = random_factory->create();

    uint64_t plain_modulus = context->context_data()->parms().plain_modulus().value();

    Encryptor encryptor(context, receiver_public_key);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    Evaluator evaluator(context);

    // compute the coefficients of the polynomial f(x) = \prod_i (x - inputs[i])
    vector<uint64_t> f_coeffs = polynomial_from_roots(inputs, plain_modulus);
    vector<Plaintext> f_coeffs_enc(f_coeffs.size());
    for (size_t i = 0; i < f_coeffs.size(); i++) {
        encode_const_vector(encoder, f_coeffs[i], f_coeffs_enc[i]);
    }

    Ciphertext f_const_term_encrypted;
    encryptor.encrypt(f_coeffs_enc[0], f_const_term_encrypted);

    vector<Ciphertext> powers(f_coeffs.size());
    // NB: powers[0] is undefined!

    for (size_t i = 0; i < receiver_inputs.size(); i++) {
        // first, compute all the powers of the receiver's input
        powers[1] = receiver_inputs[i];
        for (size_t j = 2; j < powers.size(); j++) {
            if (j & 2 == 0) {
                evaluator.square(powers[j >> 1], powers[j]);
            } else {
                evaluator.multiply(powers[j - 1], powers[1], powers[j]);
            }
            evaluator.relinearize_inplace(powers[j], relin_keys);
        }

        // now use the computed powers to evaluate f(input)
        result[i] = f_const_term_encrypted;

#ifdef DEBUG
        Decryptor decryptor(context, *receiver_key_leaked);
        cerr << "computing matches for receiver batch #" << i << endl;
        cerr << "initially the noise budget is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif

        for (size_t j = 1; j < f_coeffs.size(); j++) {
            // term = receiver_inputs[i]^j * f_coeffs[j]
            Ciphertext term;
            if (f_coeffs[j] != 0) {
                // multiply_plain does not allow the second parameter to be zero.
                evaluator.multiply_plain(powers[j], f_coeffs_enc[j], term);
                evaluator.relinearize_inplace(term, relin_keys);
                evaluator.add_inplace(result[i], term);
            }

#ifdef DEBUG
        cerr << "after term " << j << " it is " << decryptor.invariant_noise_budget(result[i]) << endl;
#endif
        }

        // now multiply the result of each computation by a random mask
        Plaintext random_mask(slot_count, slot_count);
        for (size_t j = 0; j < slot_count; j++) {
            random_mask[j] = random_nonzero_integer(random, plain_modulus);
        }
        encoder.encode(random_mask);
        evaluator.multiply_plain_inplace(result[i], random_mask);
        // since we're done computing on this, this relinearization is really
        // only helpful to decrease communication costs
        evaluator.relinearize_inplace(result[i], relin_keys);
    }

    return result;
}
