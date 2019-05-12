#include <cassert>

#include "networking.h"

const uint64_t NET_MAGIC_HELLO = 0x5052495643415453ull; // 'PRIVCATS'
const uint32_t NET_MAGIC_VECTOR_UINT64 = 0x76756938ul; // 'vui8'
const uint32_t NET_MAGIC_CIPHERTEXT = 0x63697074ul; // 'cipt'
const uint32_t NET_MAGIC_VECTOR_CIPHERTEXT = 0x76636970ul; // 'vcip'
const uint32_t NET_MAGIC_VECTOR_VECTOR_CIPHERTEXT = 0x76766369ul; // 'vvci'
const uint32_t NET_MAGIC_PUBLIC_KEY = 0x706b6579ul; // 'pkey'
const uint32_t NET_MAGIC_RELIN_KEYS = 0x72656c6eul; // 'reln'

Networking::Networking(ip::tcp::socket &socket)
    : socket(socket), read_stream(&read_buffer), write_stream(&write_buffer)
{}

void Networking::set_seal_context(shared_ptr<SEALContext> new_context) {
    seal_context = new_context;
}

uint32_t Networking::read_uint32() {
    uint8_t bytes[4];
    auto transferred = read(socket, boost::asio::buffer(&bytes, 4));
    assert(transferred == 4);
    return ((uint32_t) bytes[3]
            | ((uint32_t) bytes[2] << 8)
            | ((uint32_t) bytes[1] << 16)
            | ((uint32_t) bytes[0] << 24));
}

void Networking::write_uint32(uint32_t value) {
    uint8_t bytes[4];
    bytes[0] = value >> 24;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = (value) & 0xFF;
    auto transferred = write(socket, boost::asio::buffer(&bytes, 4));
    assert(transferred == 4);
}

uint64_t Networking::read_uint64() {
    uint64_t high = read_uint32();
    uint64_t low = read_uint32();
    return (high << 32) | low;
}

void Networking::write_uint64(uint64_t value) {
    write_uint32(value >> 32);
    write_uint32(value & 0xFFFFFFFFull);
}

void Networking::read_hello() {
    assert(read_uint64() == NET_MAGIC_HELLO);
}

void Networking::write_hello() {
    write_uint64(NET_MAGIC_HELLO);
}

void Networking::read_ciphertext(Ciphertext &ciphertext) {
    assert(seal_context);
    assert(read_uint32() == NET_MAGIC_CIPHERTEXT);
    uint32_t length = read_uint32();
    auto transferred = read(socket, read_buffer, transfer_exactly(length));
    assert(transferred == length);
    ciphertext.load(seal_context, read_stream);
}

void Networking::write_ciphertext(Ciphertext &ciphertext) {
    write_uint32(NET_MAGIC_CIPHERTEXT);
    ciphertext.save(write_stream);
    uint32_t length = write_buffer.size();
    write_uint32(length);
    auto transferred = write(socket, write_buffer, transfer_exactly(length));
    assert(transferred == length);
    write_buffer.consume(length);
}

void Networking::read_uint64s(vector<uint64_t> &values) {
    assert(read_uint32() == NET_MAGIC_VECTOR_UINT64);
    uint32_t length = read_uint32();
    values.resize(length);
    for (size_t i = 0; i < length; i++) {
        values[i] = read_uint64();
    }
}

void Networking::write_uint64s(vector<uint64_t> &values) {
    write_uint32(NET_MAGIC_VECTOR_UINT64);
    write_uint32(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        write_uint64(values[i]);
    }
}

void Networking::read_ciphertexts(vector<Ciphertext> &ciphertexts) {
    assert(read_uint32() == NET_MAGIC_VECTOR_CIPHERTEXT);
    uint32_t length = read_uint32();
    ciphertexts.resize(length);
    for (size_t i = 0; i < length; i++) {
        read_ciphertext(ciphertexts[i]);
    }
}

void Networking::write_ciphertexts(vector<Ciphertext> &ciphertexts) {
    write_uint32(NET_MAGIC_VECTOR_CIPHERTEXT);
    write_uint32(ciphertexts.size());
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        write_ciphertext(ciphertexts[i]);
    }
}

void Networking::read_ciphertexts_2d(vector<vector<Ciphertext>> &ciphertexts) {
    assert(read_uint32() == NET_MAGIC_VECTOR_VECTOR_CIPHERTEXT);
    uint32_t length = read_uint32();
    ciphertexts.resize(length);
    for (size_t i = 0; i < length; i++) {
        read_ciphertexts(ciphertexts[i]);
    }
}

void Networking::write_ciphertexts_2d(vector<vector<Ciphertext>> &ciphertexts) {
    write_uint32(NET_MAGIC_VECTOR_VECTOR_CIPHERTEXT);
    write_uint32(ciphertexts.size());
    for (size_t i = 0; i < ciphertexts.size(); i++) {
        write_ciphertexts(ciphertexts[i]);
    }
}

void Networking::read_public_key(PublicKey &public_key) {
    assert(seal_context);
    assert(read_uint32() == NET_MAGIC_PUBLIC_KEY);
    uint32_t length = read_uint32();
    auto transferred = read(socket, read_buffer, transfer_exactly(length));
    assert(transferred == length);
    public_key.load(seal_context, read_stream);
}

void Networking::write_public_key(PublicKey &public_key) {
    write_uint32(NET_MAGIC_PUBLIC_KEY);
    public_key.save(write_stream);
    uint32_t length = write_buffer.size();
    write_uint32(length);
    auto transferred = write(socket, write_buffer, transfer_exactly(length));
    assert(transferred == length);
    write_buffer.consume(length);
}

void Networking::read_relin_keys(RelinKeys &relin_keys) {
    assert(seal_context);
    assert(read_uint32() == NET_MAGIC_RELIN_KEYS);
    uint32_t length = read_uint32();
    auto transferred = read(socket, read_buffer, transfer_exactly(length));
    assert(transferred == length);
    relin_keys.load(seal_context, read_stream);
}

void Networking::write_relin_keys(RelinKeys relin_keys) {
    write_uint32(NET_MAGIC_RELIN_KEYS);
    relin_keys.save(write_stream);
    uint32_t length = write_buffer.size();
    write_uint32(length);
    auto transferred = write(socket, write_buffer, transfer_exactly(length));
    assert(transferred == length);
    write_buffer.consume(length);
}
