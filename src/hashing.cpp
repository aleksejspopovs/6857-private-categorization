#include <cassert>

#include "aes.h"

#include "hashing.h"

using namespace std;

uint64_t aes_hash(AES &aes, size_t bits, uint64_t value) {
	assert(bits < 64);
	auto ciphertext = aes.encrypt(0, value);
	return (ciphertext.second ^ value) & ((1ull << bits) - 1);
}

size_t loc_aes_hash(AES &aes, size_t m, uint64_t value) {
	return aes_hash(aes, m, value >> m) ^ (value & ((1ull << m) - 1));
}

bool cuckoo_hash(shared_ptr<UniformRandomGenerator> random,
	             vector<uint64_t> &inputs,
	             size_t m,
	             vector<pair<uint64_t, size_t>> &buckets,
	             vector<uint64_t> &seeds)
{
	assert(buckets.size() == (1 << m));

	vector<AES> aes(seeds.size());
	for (size_t i = 0; i < seeds.size(); i++) {
		aes[i].set_key(0, seeds[i]);
	}

	for (uint64_t s : inputs) {
		bool resolved = false;
		pair<uint64_t, size_t> current_item = make_pair(
			s,
			random_integer(random, seeds.size())
		);

		// TODO: keep track of # of operations and abort if exceeding some limit
		while (!resolved) {
			size_t loc = loc_aes_hash(aes[current_item.second], m, current_item.first);

			buckets[loc].swap(current_item);

			if (current_item == BUCKET_EMPTY) {
				resolved = true;
			} else {
				size_t old_hash = current_item.second;
				while (current_item.second == old_hash) {
					current_item.second = random_integer(random, seeds.size());
				}
			}
		}
	}

	return true;
}

bool complete_hash(shared_ptr<UniformRandomGenerator> random,
	               vector<uint64_t> &inputs,
                   size_t m,
                   size_t capacity,
                   vector<pair<uint64_t, size_t>> &buckets,
                   vector<uint64_t> &seeds)
{
	assert(buckets.size() == capacity << m);

	vector<AES> aes(seeds.size());
	for (size_t i = 0; i < seeds.size(); i++) {
		aes[i].set_key(0, seeds[i]);
	}

	vector<size_t> capacity_used(1 << m);

	for (uint64_t s : inputs) {
		for (size_t i = 0; i < seeds.size(); i++) {
			size_t loc = loc_aes_hash(aes[i], m, s);

			if (capacity_used[loc] == capacity) {
				// all slots in the bucket are used, so we cannot add this
				// element
				return false;
			}

			// now we want to pick a random unoccupied slot in this bucket.
			// to do so, pick a number slot_index in 0..(current capacity - 1)
			// and traverse the bucket looking for the slot_indexth unoccupied
			// slot.
			size_t slot_index = random_integer(random, capacity - capacity_used[loc]);
			for (size_t j = 0; j < capacity; j++) {
				if (buckets[capacity * loc + j] == BUCKET_EMPTY) {
					if (slot_index == 0) {
						buckets[capacity * loc + j] = make_pair(s, i);
						break;
					}
					slot_index--;
				}
			}
			capacity_used[loc]++;
		}
	}

	return true;
}
