# Original VLSE layout

`TripleVacuumFilter` splits a 128-bit token into three 64-bit components and stores them in three independent instances of the upstream Vacuum Filter:

- 15-bit fingerprint for the high half;
- 15-bit fingerprint for the low half;
- 13-bit fingerprint for `high XOR low`.

The associated payload is stored in a `std::map`. Empty filter slots can be filled with short dummy fingerprints through `FillEmptySlots()`.

From the repository root:

```bash
cmake -S . -B build
cmake --build build --target original_vlse_demo
./build/original_vlse/original_vlse_demo
```
