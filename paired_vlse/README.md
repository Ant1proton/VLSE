# VLSE example

Follow the [root README](../README.md) to install dependencies and configure the
build. From the repository root, build and run the example:

```bash
cmake --build build-release --target paired_vlse_demo
./build-release/paired_vlse/paired_vlse_demo
```

Run a configurable experiment:

```bash
./build-release/benchmarks/vlse_protocol_benchmark \
  --keywords 16384 --queries 1000 --dmax 1 --seed 1
```
