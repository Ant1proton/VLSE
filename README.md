# VLSE examples

This repository contains two compact C++ implementations:

- `original_vlse/`: three independent upstream Vacuum Filters (`15 + 15 + 13` bits) with a `std::map` payload table.
- `paired_vlse/`: one 43-bit Vacuum Filter whose fingerprint and payload move as a single record.

The repository is a runnable implementation example, not a benchmark package.

## Requirements

- CMake 3.16 or newer
- A C++17 compiler
- OpenSSL development files
- Git (for the Vacuum-Filter submodule)

Ubuntu/Debian:

```bash
sudo apt-get install build-essential cmake git libssl-dev
```

macOS with Homebrew:

```bash
brew install cmake openssl
```

## Build and test

```bash
git clone --recurse-submodules https://github.com/Ant1proton/VLSE.git
cd VLSE
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Run either example directly:

```bash
./build/original_vlse/original_vlse_demo
./build/paired_vlse/paired_vlse_demo
```

If the repository was cloned without submodules, initialize the dependency with:

```bash
git submodule update --init --recursive
```

Each implementation directory contains a short description of its layout.
