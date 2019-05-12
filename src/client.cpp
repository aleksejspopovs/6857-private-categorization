#include <cassert>
#include <iostream>

#include "boost/asio.hpp"

#include "networking.h"

using namespace std;
using namespace boost::asio;

int main()
{
    vector<uint64_t> inputs = {0x02, 0x07, 0x05, 0xfe};
    size_t input_bits = 32;
    unsigned short port = 9999;

    io_context context;
    ip::tcp::socket socket(context);
    ip::tcp::resolver resolver(context);
    connect(socket, resolver.resolve("localhost", "9999", resolver.numeric_service));
    Networking net(socket);

    cout << "connected, waiting for hello and set size" << endl;
    net.read_hello();
    size_t sender_size = net.read_uint32();

    cout << "picking params" << endl;
    PSIParams params(inputs.size(), sender_size, input_bits);
    params.generate_seeds();
    net.set_seal_context(params.context);
    PSIReceiver receiver(params);

    cout << "sending hello, set size, seeds, pk, relin keys" << endl;
    net.write_hello();
    net.write_uint32(inputs.size());
    net.write_uint64s(params.seeds);
    net.write_public_key(receiver.public_key());
    net.write_relin_keys(receiver.relin_keys());

    cout << "encrypting inputs" << endl;
    vector<bucket_slot> buckets;
    auto encrypted_inputs = receiver.encrypt_inputs(inputs, buckets);

    cout << "sending inputs" << endl;
    net.write_ciphertexts_2d(encrypted_inputs);

    cout << "waiting for encrypted matches" << endl;
    vector<Ciphertext> encrypted_matches;
    net.read_ciphertexts(encrypted_matches);

    cout << "decrypting matches" << endl;
    auto matches = receiver.decrypt_matches(encrypted_matches);

    cout << matches.size() << " matches found: ";
    for (size_t i : matches) {
        assert(i < buckets.size());
        assert(buckets[i] != BUCKET_EMPTY);
        cout << inputs[buckets[i].first] << " ";
    }
    cout << endl;
}
