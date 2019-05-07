#include <iostream>

#include "seal/seal.h"

#include "psi.h"


using namespace std
using namespace seal

map<int,string> cuckooHash(set<string> inputs,int buckets,int h,function<int buckets,hashfunctions> hashFunctionGenerator)
	/** Given a set of strings and a number of buckets, hashes exactly one string to each bucket. hashFunctionGenerator should be a method that given a number of buckets,
	returns a hash function from strings to that number of buckets. This could be implemented for example as AES(r,s) mod buckets. 
	**/
	list<function> hashFunctions;  //not sure what the type of a hash functioyn will be.
	for (int i=0;i<h;i++){
		hashFunctions.insert(hashFunctionGenerator(buckets));
	 }
	map<int,string> bucketPlacement;
	map<string, int> hashNumberUsed;
	for (auto s: inputs){
		bool resolved=false;
		int placement=hashFunctions[0](s);
		hashNumberUsed[s]=0;
		string currentString=s;
		while(!resolved){
			if (bucketPlacement.find(placement)=bucketPlacement.end()){//is this actually how you check that something is in the map?
				resolved=true;
				bucketPlacement[placement].insert(s)
			}
			else{
				//if the bucket is full, you move its inhabitant to a new location
				currentString=bucketPlacement[placement]
				bucketPlacement[placement]=s
				hashNumberUsed[currentString]+=1
				placement=hashFunctions[hashNumberUsed[currentString]](currentString)
			}
		}
	}
	return bucketPlacement; //should probably also return the hash functions?

