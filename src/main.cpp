#include <iostream>

#include "seal/seal.h"

using namespace std;
using namespace seal;

int main()
{
    /* simplified example adapted from
       https://github.com/Microsoft/SEAL/blob/master/native/examples/examples.cpp
     */

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(2048));
    parms.set_plain_modulus(1 << 8);

    auto context = SEALContext::Create(parms);

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    IntegerEncoder encoder(context);

    /* suppose we want to implement a simplistic protocol where Alice encrypts
       two numbers x and y, and wants Bob to compute (x + y) * x for her. */
    cout << "suppose Alice wants Bob to compute (x + y) * x for her, for some secret inputs x and y" << endl;
    cout << endl;

    /* stage 1: Alice encrypts her inputs, e.g. x = 5, y = -3 */
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    int x = 5;
    int y = -3;
    cout << "Alice sets x = " << x << ", y = " << y << endl;

    Plaintext x_plain = encoder.encode(x);
    Plaintext y_plain = encoder.encode(y);
    cout << "encoded as polynomials, that's x = " << x_plain.to_string() << ", y = " << y_plain.to_string() << endl;

    Ciphertext x_encrypted, y_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);
    encryptor.encrypt(y_plain, y_encrypted);
    cout << "Alice encrypts the two inputs. each of them currently has a noise budget of "
         << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;
    cout << endl;

    /* stage 2: suppose Alice has sent x_encrypted and y_encrypted over to Bob.
       now Bob evaluates the formula over the ciphertexts. */
    Evaluator evaluator(context);
    /* the operations are in-place: they overwrite the first argument */
    evaluator.add_inplace(y_encrypted, x_encrypted);
    cout << "Bob computes z = (x + y) over the ciphertexts. the noise budget is still "
         << decryptor.invariant_noise_budget(y_encrypted) << " bits, because addition is cheap" << endl;
    /* now y_encrypted holds E(x + y) */
    evaluator.multiply_inplace(y_encrypted, x_encrypted);
    cout << "Bob computes w = z * x over the ciphertexts. the noise budget is down to "
         << decryptor.invariant_noise_budget(y_encrypted) << " bits, because multiplication is expensive" << endl;
    /* now y_encrypted holds E((x + y) * x), so Bob sends that over to Alice */
    cout << endl;

    /* stage 3: Alice decryptes the answer. notice that this is the only stage
       where we use the private key. */

    Plaintext result;
    decryptor.decrypt(y_encrypted, result);
    cout << "Alice gets the encrypted result and decrypts, getting " << result.to_string() << endl;
    cout << "converting back to an integer, that's " << encoder.decode_int32(result) << endl;

    return 0;
}
