
# Private Categorization

## Disclaimer

The code in this repository has not undergone a security audit and is **not suitable for deployment in production systems**. The authors make no guarantees (including, but not limited to, regarding the safety, security, or correctness) of the code in this repository.

## Introduction

Private Categorization is an implementation of a homomorphic encryption-based protocol for Labeled Unbalanced Public Set Intersection.

In Private Set Intersection, two parties, a *sender* and a *receiver*, hold a set each (say S and R, respectively). Their goal is to exchange some information such that the receiver comes to learn the intersection of the two sets, but nothing about which other elements might or might not be present in S, and the sender learns no new information.

Unbalanced PSI is the problem of doing this efficiently when the sender's set is very large but the receiver's set is relatively small. Labeled PSI is the problem where the sender also holds a function f that maps each element of S to a *label*, and the receiver must also learn f(x) for all x in the intersection of S and R, but not for any other x.

Private Categorization was developed primarily as part of a final project for *6.857 Computer and Network Security*, a security class at MIT, in the Spring 2019 semester.

## Building and running

The software in this repository is known to compile on Linux using the GCC 8.3.0 compiler.

It is intended to be reasonably portable, but three known caveats exist:

- the implementation of arithmetic modulo p uses the type `__uint128_t`, which is a GCC-specific extension. if your compiler does not support it, you might be able to substitute another 128-bit type for it in `src/polynomials.h`, or you can limit yourself to small (32-bit long) moduli by defining the `MODULUS_IS_SMALL` symbol during compilation.
- the AES implementation in `aes.cpp` uses x86-specific intrinsics.
- SEAL's serialization routines are not endianness-aware, i.e. they produce different results on platforms with different endianness. therefore the `pc_client` binary cannot communicate with a `pc_server` that is running on a machine with a different endianness.

Follow your operating system's instructions to install [CMake](https://cmake.org/) and [Boost](https://www.boost.org/). You only need the "Boost headers" if your operating system makes such a distinction.

Follow the [SEAL installation instructions](https://github.com/Microsoft/SEAL#linux-and-macos) to build and install SEAL.

If you followed the global install instructions for SEAL, build Private Categorization like this:

    cd src
    cmake .
    make

If you followed the local install instruction for SEAL to install it into `/path/to/seal`, build PC like this:

    cd src
    cmake -DCMAKE_PREFIX_PATH=/path/to/seal .
    make

The binaries for the project will be output to `bin/`. You can now run `bin/private_categorization` to see an example PSI protocol run,
`bin/pc_client` and `bin/pc_server` to do the same over the network, or
`bin/benchmark` to measure the performance of the protocol with given parameters.

## References and acknowledgements

This software implements algorithms described in these papers:

- [CLR17] Hao Chen, Kim Laine, and Peter Rindal. Fast Private Set Intersection from Homomorphic Encryption. Cryptology ePrint Archive, Report 2017/299, 2017. https://eprint.iacr.org/2017/299


- [CHLR18] Hao Chen, Zhicong Huang, Kim Laine, and Peter Rindal. *Labeled PSI from Fully Homomorphic Encryption with Malicious Security*. Cryptology ePrint Archive, Report 2018/787, 2018. https://eprint.iacr.org/2018/787

This software contains an implementation of hardware-accelerated AES based on the public domain [implementation](https://github.com/ladnir/cryptoTools/blob/0bbb3a586087fbe85fcd6f4e1ffb43079ff6f6ca/cryptoTools/Crypto/AES.h) in Peter Rindal's [cryptoTools](https://github.com/ladnir/cryptoTools/) project.

## License

Copyright (C) 2019 Aleksejs Popovs <aleksejs@popovs.lv>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

A copy of the GNU General Public License can be found in the file `LICENSE` in the root directory of this repository. You can also obtain a copy of the license [online](https://www.gnu.org/licenses/).



