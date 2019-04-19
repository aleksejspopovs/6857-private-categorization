# Private Categorization

## Building and running

### On Linux/macOS

Follow the [SEAL installation instructions](https://github.com/Microsoft/SEAL#linux-and-macos) to build and install SEAL.

If you followed the global install instructions for SEAL, build Private Categorization like this:

    cd src
    cmake .
    make

If you followed the local install instruction for SEAL to install it into `/path/to/seal`, build PC like this:

    cd src
    cmake -DCMAKE_PREFIX_PATH=/path/to/seal .
    make

The binary for the project will be output to `bin/private_categorization`. If you run it, you should see output like this:

    suppose Alice wants Bob to compute (x + y) * x for her, for some secret inputs x and y

    Alice sets x = 5, y = -3
    encoded as polynomials, that's x = 1x^2 + 1, y = FFx^1 + FF
    Alice encrypts the two inputs. each of them currently has a noise budget of 36 bits

    Bob computes z = x + y over the ciphertexts. the noise budget is still 35 bits, because addition is cheap
    Bob computes w = z * x over the ciphertexts. the noise budget is down to 17 bits, because multiplication is expensive

    Alice gets the encrypted result and decrypts, getting 1x^4 + FFx^3 + 1x^2 + FFx^1
    converting back to an integer, that's 10


If you make changes to the project, you only need to rerun `make`, not `cmake` (unless you added or removed source code files).

### On Windows

TODO
