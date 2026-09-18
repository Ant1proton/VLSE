# VLSE

## Tested environment

The current implementation was built and tested with:

| Component | Version |
|---|---|
| Hardware | Apple M3, 16 GB RAM |
| Operating system | macOS 15.7.3 (24G419) |
| Language | C++17 |
| Compiler | Homebrew LLVM/Clang 21.1.3 |
| CMake | 4.1.2 |
| NTL | 11.5.1 |
| GMP | 6.3.0 |
| Crypto++ | 8.9.0 |
| OpenSSL | 3.6.0 |
| Vacuum Filter | `wuwuz/Vacuum-Filter` commit `ec234bfc189af9e6180688495535c623ad352190` |

The OPRF backend uses the checked-in
`ffc3072-q256-shake256-v1` parameter set: a 3072-bit finite-field modulus,
a 256-bit prime-order subgroup, SHAKE256-based hash-to-subgroup, and 384-byte
fixed-width group-element encoding. The parameter file is
`common/parameters/ffc3072_q256.pem`.

## Install dependencies

Clone the repository and its Vacuum Filter submodule:

```bash
git clone --recurse-submodules https://github.com/Ant1proton/VLSE.git
cd VLSE
```

If the repository was cloned without `--recurse-submodules`, run:

```bash
git submodule update --init --recursive
```

### macOS with Homebrew

```bash
brew install cmake llvm ntl gmp cryptopp openssl@3
```

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git \
  libntl-dev libgmp-dev libcrypto++-dev libssl-dev
```

## Build

On Apple Silicon macOS, the following command uses the same compiler family as
the tested build:

```bash
cmake -S . -B build-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DCMAKE_PREFIX_PATH="/opt/homebrew;/opt/homebrew/opt/openssl@3"
cmake --build build-release -j
```

On Linux, or when the default compiler and dependency paths are already
configured:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
```

## Test

```bash
ctest --test-dir build-release --output-on-failure
```

The test suite contains the OPRF consistency test, the original and paired
VLSE examples, the paired collision test, and protocol smoke tests.

## Run the latest paired VLSE implementation

Run the small end-to-end example:

```bash
./build-release/paired_vlse/paired_vlse_demo
```

Run the configurable VLSE protocol driver:

```bash
./build-release/benchmarks/vlse_protocol_benchmark \
  --layout paired \
  --keywords 4096 \
  --queries 1000 \
  --dmax 1 \
  --seed 1
```

Arguments:

- `--keywords N`: number of keyword records.
- `--queries Q`: number of member queries; `Q` must not exceed `N`.
- `--dmax D`: fixed label-list capacity; supported values are
  `1`, `5`, `10`, `15`, and `20`.
- `--seed S`: nonzero reproducibility seed.
- `--layout paired`: selects the latest 43-bit paired Vacuum Filter path.

The program prints one machine-readable `RESULT` line containing Setup,
dummy-padding, OPRF, lookup/decryption, object-size, communication, collision,
relocation, rollback, and correctness counters.
