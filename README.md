# VLSE

C++17 implementation and local benchmarks for VLSE and LSE.

## Dependencies

Install CMake, a C++17 compiler, NTL, GMP, Crypto++, and OpenSSL.

macOS with Homebrew:

```sh
brew install cmake llvm ntl gmp cryptopp openssl@3
```

Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake git \
  libntl-dev libgmp-dev libcrypto++-dev libssl-dev
```

## Get the source

```sh
git clone --recurse-submodules https://github.com/Ant1proton/VLSE.git
cd VLSE
```

For an existing checkout, initialize the dependency:

```sh
git submodule update --init --recursive
```

## Build and test

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j 4
ctest --test-dir build-release --output-on-failure
```

On Apple Silicon macOS, configure with Homebrew LLVM and library paths:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  '-DCMAKE_PREFIX_PATH=/opt/homebrew;/opt/homebrew/opt/openssl@3'
cmake --build build-release -j 4
ctest --test-dir build-release --output-on-failure
```

## Run

Run the example:

```sh
./build-release/paired_vlse/paired_vlse_demo
```

Run VLSE with 16,384 keyword records and 1,000 queries:

```sh
./build-release/benchmarks/vlse_protocol_benchmark \
  --keywords 16384 --queries 1000 --dmax 1 --seed 1
```

Run the LSE benchmark with the same workload settings:

```sh
./build-release/benchmarks/lse_protocol_benchmark \
  --keywords 16384 --queries 1000 --dmax 1 --seed 1
```

| Argument | Meaning |
|---|---|
| `--keywords N` | Number of keyword records; positive integer. |
| `--queries Q` | Number of member queries; between 1 and N. |
| `--dmax D` | Label capacity per record: 1, 5, 10, 15, or 20. |
| `--seed S` | Positive seed for keyword generation and index layout. |

The generated workload fills every genuine record with D labels. Cryptographic
keys and blinds use system randomness. Each executable prints a `RESULT` line.
`online_ms` is the total time for all Q queries: token generation plus lookup and
decryption. Divide by Q for the average time per query. Setup, offline blind
precomputation, and network delay are excluded from online time.

VLSE authenticates all candidate components, collects valid document IDs, and
sorts and deduplicates the result before ending the search timer. Expected
results are checked after timing.

## Batch runs

Run a smoke check:

```sh
bash scripts/run_smoke.sh
```

Run paired VLSE/LSE measurements on macOS (requires Python 3.10 or newer):

```sh
VLSE_COMPARE_SIZES="16384" \
VLSE_COMPARE_ROUNDS=3 \
VLSE_COMPARE_QUERIES=1000 \
VLSE_COMPARE_DMAX=1 \
bash scripts/run_paired_vs_lse.sh results/paired_vs_lse
```

Choose a new or empty output directory. The script saves logs and CSV summaries.
It waits for background CPU activity to settle before each measurement.
