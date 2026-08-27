# Paired VLSE layout

`PairedVacuumFilter<43, Payload>` stores a 43-bit fingerprint and its payload as one logical record. Sorting, eviction and rollback always move both fields together. Its bit codec supports fingerprints from 5 to 64 bits, including bucket encodings longer than one machine word.

The example uses a fixed-size AES-128-GCM label. A lookup returns every matching slot; authenticated decryption selects the label bound to the full query token. `FillEmptySlots()` pads remaining slots with dummy records.

From the repository root:

```bash
cmake -S . -B build
cmake --build build --target paired_vlse_demo
./build/paired_vlse/paired_vlse_demo
```
