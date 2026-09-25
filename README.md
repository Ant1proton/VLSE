# VLSE

## Get the source

```bash
git clone --recurse-submodules https://github.com/Ant1proton/VLSE.git
cd VLSE
```

If the repository was cloned without its dependency:

```bash
git submodule update --init --recursive
```

For a source archive that includes `Vacuum-Filter/hashutil.h`, extract the archive
and run the following commands from its `VLSE` directory.

## Install dependencies

A C++17 compiler, CMake, NTL, GMP, Crypto++, and OpenSSL are required.

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

### Apple Silicon macOS

```bash
cmake -S . -B build-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DCMAKE_PREFIX_PATH="/opt/homebrew;/opt/homebrew/opt/openssl@3"
cmake --build build-release -j
```

### Linux

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
```

## Test

```bash
ctest --test-dir build-release --output-on-failure
```

## Run VLSE

Run the example:

```bash
./build-release/paired_vlse/paired_vlse_demo
```

Run a configurable experiment:

```bash
./build-release/benchmarks/vlse_protocol_benchmark \
  --keywords 16384 --queries 1000 --dmax 1 --seed 1
```

| Argument | Meaning |
|---|---|
| `--keywords N` | Number of keyword records; positive integer. |
| `--queries Q` | Number of member queries; positive integer no greater than `N`. |
| `--dmax D` | Label capacity per record: `1`, `5`, `10`, `15`, or `20`. Use `1` for a single label. |
| `--seed S` | Nonzero seed for the generated workload and filter layout. |

The program builds and pads the database, then checks the query results. It prints
one `RESULT` line containing timings, object size, communication counts, and
correctness counters.

## Run the VLSE/LSE comparison

The batch script requires macOS. From the repository root:

```bash
bash scripts/run_paired_vs_lse.sh results/paired_vs_lse
```

The default run uses 16,384, 32,768, 65,536, 131,072, and 262,144 keyword records,
three rounds per size, 1,000 queries per round, and one label per record. Choose a
new or empty output directory for each experiment.

For a smaller run:

```bash
VLSE_COMPARE_SIZES="1024" \
VLSE_COMPARE_ROUNDS=1 \
VLSE_COMPARE_QUERIES=1000 \
bash scripts/run_paired_vs_lse.sh results/small_run
```

The script writes individual logs under `logs/` and creates `raw_results.csv`,
`summary.csv`, `query_checkpoints.csv`, and `communication_points.csv` in the
selected output directory.
