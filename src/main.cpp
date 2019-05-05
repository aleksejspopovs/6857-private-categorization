#include <iostream>

#include "seal/seal.h"

#include "psi.h"

using namespace std;
using namespace seal;

int main()
{
    // all integers are going to be printed as hex now
    cout << hex;

    // step 1: agreeing on parameters. currently just hard-coded, TODO.
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    // for batching to work, the plain modulus must be a prime that's equal
    // to 1 mod (2 * poly_modulus_degree)
    parms.set_plain_modulus((8192* 2 * 4) + 1);
    auto context = SEALContext::Create(parms);

    // step 2: receiver generates keys and inputs with the keys
    PSIReceiver user(context, 8);
    vector<uint64_t> receiver_inputs = {0x11, 0x22, 0xca, 0xfe};
    auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs);

    cout << "User's set: ";
    for (uint64_t x : receiver_inputs) {
        cout << x << " ";
    }
    cout << endl;

    // step 3: the sender evaluates polynomials
    // (after having received the receiver's public key and encrypted inputs)
    PSISender server(context, 8);
    vector<uint64_t> sender_inputs = {0x02, 0x03, 0x04, 0x05, 0x22, 0xfe};
    auto sender_matches = server.compute_matches(
        sender_inputs,
        user.public_key(),
        user.relin_keys(),
        receiver_encrypted_inputs
    );

    cout << "Sender's set: ";
    for (uint64_t x : sender_inputs) {
        cout << x << " ";
    }
    cout << endl;

    // step 4: the receiver decrypts the matches
    // (after having received the encrypted matches)
    auto receiver_matches = user.decrypt_matches(sender_matches);

    cout << "Matches: ";
    for (size_t i : receiver_matches) {
        if (i < receiver_inputs.size()) {
            cout << i << ":" << receiver_inputs[i] << " ";
        } else {
            cout << i << ":INVALID ";
        }
    }
    cout << endl;

    return 0;
}
