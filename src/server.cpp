#include <cstdint>
#include <iostream>

#include "boost/asio.hpp"

#include "networking.h"

using namespace std;
using namespace boost::asio;

int main()
{
    vector<uint64_t> inputs = {0x01, 0x02, 0x03, 0x04, 0x07, 0x22, 0xca, 0xfe};
    size_t input_bits = 32;
    unsigned short port = 9999;

    io_context context;
    ip::tcp::acceptor acceptor(context);
    ip::tcp::endpoint endpoint(ip::tcp::v4(), port);
    acceptor.open(endpoint.protocol());
    acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();

    cout << "listening" << endl;

    ip::tcp::socket socket(context);
    acceptor.accept(socket);
    Networking net(socket);

    cout << "accepted, sending hello and set size" << endl;
    net.write_hello();
    net.write_uint32(inputs.size());

    cout << "waiting for hello" << endl;
    net.read_hello();
    cout << "waiting for set size" << endl;
    size_t receiver_size = net.read_uint32();
    cout << "waiting for seeds" << endl;
    vector<uint64_t> seeds;
    net.read_uint64s(seeds);

    // we can now establish the PSI parameters, which creates the SEAL context,
    // which we need to receive keys and ciphertexts
    PSIParams params(receiver_size, inputs.size(), input_bits);
    params.set_seeds(seeds);
    net.set_seal_context(params.context);

    cout << "waiting for public key" << endl;
    PublicKey receiver_pk;
    net.read_public_key(receiver_pk);
    cout << "waiting for relin keys" << endl;
    RelinKeys receiver_rk;
    net.read_relin_keys(receiver_rk);
    cout << "waiting for inputs" << endl;
    vector<vector<Ciphertext>> receiver_inputs;
    net.read_ciphertexts_2d(receiver_inputs);

    cout << "computing matches" << endl;

    PSISender sender(params);
    auto sender_matches = sender.compute_matches(
        inputs,
        receiver_pk,
        receiver_rk,
        receiver_inputs
    );

    cout << "sending matches" << endl;
    net.write_ciphertexts(sender_matches);
}
