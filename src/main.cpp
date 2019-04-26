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
    parms.set_poly_modulus_degree(2048);
    // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(2048));
    /* NB: THIS IS UNSAFE. TODO: figure out how to pick the right parameters
       to get enough security, but also enough budget for computations. */
    vector<SmallModulus> modulus = {DefaultParams::small_mods_60bit(0),
                                    DefaultParams::small_mods_60bit(1),
                                    DefaultParams::small_mods_60bit(2),
                                    DefaultParams::small_mods_60bit(3)};
    parms.set_coeff_modulus(modulus);
    parms.set_plain_modulus(1 << 8);
    auto context = SEALContext::Create(parms);

    // step 2: receiver generates keys and inputs with the keys
    PSIReceiver user(context, 8);
    vector<int> receiver_inputs = {0x11, 0x22, 0xca, 0xfe};
    auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs);

    cout << "User's set: ";
    for (int x : receiver_inputs) {
        cout << x << " ";
    }
    cout << endl;

    // step 3: the sender evaluates polynomials
    // (after having received the receiver's public key and encrypted inputs)
    PSISender server(context, 8);
    vector<int> sender_inputs = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x22, 0xfe};
    auto sender_matches = server.compute_matches(sender_inputs, user.public_key(), receiver_encrypted_inputs);

    cout << "Sender's set: ";
    for (int x : sender_inputs) {
        cout << x << " ";
    }
    cout << endl;

    // step 4: the receiver decrypts the matches
    // (after having received the encrypted matches)
    auto receiver_matches = user.decrypt_matches(sender_matches);

    cout << "Matches: ";
    for (int i : receiver_matches) {
        cout << receiver_inputs[i] << " ";
    }
    cout << endl;

    return 0;
}
