#pragma once
#include <cstdint>
#include <utility>
#include <vector>

#include "random.h"

typedef pair<size_t, size_t> bucket_slot;

const bucket_slot BUCKET_EMPTY = make_pair(0xFFFFFFFFul, 0xFFFFFFFFul);

/* Given a set of inputs, a number of buckets, and seeds for a hash function,
   performs permutation-based cuckoo hashing to put at most one element in each
   bucket.
   Permutation-based hashing means that, after hashing, it is safe to drop the
   last m bits of all the inputs in the table.
   The number of buckets is 2^m. Non-empty buckets will contain
   (input_index, seed_index), empty ones will be equal to BUCKET_EMPTY.
   Seeds should be random 64-bit values.
*/
bool cuckoo_hash(shared_ptr<UniformRandomGenerator> random,
                 vector<uint64_t> &inputs,
                 size_t m,
                 vector<bucket_slot> &buckets,
                 vector<uint64_t> &seeds);

/* Given a set of inputs, a number of buckets, and seeds for a hash function,
   places every input, hashed with *every* function, into the corresponding
   bucket, using permutation-based hashing.
   The number of buckets is 2^m. Non-empty buckets will contain
   (input_index, seed_index), empty ones will be equal to BUCKET_EMPTY.
   jth element of bucket number i is stored in buckets[i * capacity + j].
   Seeds should be random 64-bit values.
*/
bool complete_hash(shared_ptr<UniformRandomGenerator> random,
                   vector<uint64_t> &inputs,
                   size_t m,
                   size_t capacity,
                   vector<bucket_slot> &buckets,
                   vector<uint64_t> &seeds);
