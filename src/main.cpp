#include <iostream>

#include "seal/seal.h"

#include "psi.h"

using namespace std;
using namespace seal;

int main()
{
    // all integers are going to be printed as hex now
    cout << hex;

    vector<uint64_t> receiver_inputs = {0x11, 0x22, 0xca, 0xfe};
    vector<uint64_t> sender_inputs = {0x02, 0x03, 0x04, 0x05, 0x22, 0xfe};

    // step 1: agreeing on parameters.
    PSIParams params(receiver_inputs.size(), sender_inputs.size(), 20);
    params.generate_seeds();

    // step 2: receiver generates keys and inputs with the keys
    PSIReceiver user(params);
    auto receiver_encrypted_inputs = user.encrypt_inputs(receiver_inputs);

    cout << "User's set: ";
    for (uint64_t x : receiver_inputs) {
        cout << x << " ";
    }
    cout << endl;

    // step 3: the sender evaluates polynomials
    // (after having received the receiver's public key and encrypted inputs)
    PSISender server(params);
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
