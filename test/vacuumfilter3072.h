// VacuumFilter3072_Enhanced.h
#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include "xxh3.h"
#include <blake3.h>
#include <NTL/ZZ.h>

using namespace NTL;
using TokenZZ = ZZ;

const size_t kMaxCuckooCount = 500;
const size_t kTagsPerBucket = 4;

struct VictimCache {
    size_t index;
    uint32_t tag;
    bool used;
};

class AltSeedManager {
public:
    AltSeedManager() {
        for (int i = 0; i < 8; i++) {
            seeds.push_back(rand());
        }
    }
    uint64_t GetSeed(int round) const {
        return seeds[round % seeds.size()];
    }
private:
    std::vector<uint64_t> seeds;
};

class Histogram {
public:
    void Add(size_t index) {
        std::lock_guard<std::mutex> lock(mtx);
        freq[index]++;
    }
    void PrintHotspots(size_t threshold = 3) {
        std::cout << "\n[冲突热点位置] 超过 " << threshold << " 次冲突的位置:" << std::endl;
        for (auto& p : freq) {
            if (p.second >= threshold)
                std::cout << "桶 " << p.first << ": " << p.second << " 次\n";
        }
    }
private:
    std::unordered_map<size_t, size_t> freq;
    std::mutex mtx;
};

Histogram conflictHistogram;
AltSeedManager altSeeds;

class Table {
public:
    std::vector<std::vector<uint32_t>> buckets;

    Table(size_t size) {
        buckets.resize(size, std::vector<uint32_t>(kTagsPerBucket, 0));
    }

    bool Insert(size_t index, uint32_t tag, bool kickout, uint32_t& oldtag, uint32_t tags[4]) {
        auto& bucket = buckets[index];
        for (size_t i = 0; i < kTagsPerBucket; ++i) {
            if (bucket[i] == 0) {
                bucket[i] = tag;
                return true;
            }
        }
        if (!kickout) return false;
        oldtag = bucket[0];
        bucket[0] = tag;
        for (int i = 0; i < kTagsPerBucket; i++) tags[i] = bucket[i];
        return true;
    }

    bool Find(size_t index, uint32_t tag) const {
        const auto& bucket = buckets[index];
        for (auto x : bucket)
            if (x == tag) return true;
        return false;
    }
};

template <size_t bits_per_item>
class VacuumFilter3072 {
public:
    VacuumFilter3072(size_t s) : size(s), victim_{0, 0, false} {
        table = new Table(size);
    }
    ~VacuumFilter3072() {
        delete table;
    }

    bool Insert(const TokenZZ& token) {
        uint32_t fp = CompressZZToFingerprint(token);
        auto indices = AllIndices(fp);

        std::lock_guard<std::mutex> lock(mtx);
        for (auto idx : indices) conflictHistogram.Add(idx);

        uint32_t oldtag, tags[4];
        for (auto idx : indices)
            if (table->Insert(idx, fp, false, oldtag, tags)) return true;

        return Evict(indices[0], fp);
    }

    bool Contains(const TokenZZ& token) {
        uint32_t fp = CompressZZToFingerprint(token);
        auto indices = AllIndices(fp);

        std::lock_guard<std::mutex> lock(mtx);
        for (auto idx : indices)
            if (table->Find(idx, fp)) return true;

        if (victim_.used && victim_.tag == fp &&
            std::find(indices.begin(), indices.end(), victim_.index) != indices.end())
            return true;

        return false;
    }

    void PrintConflictInfo() const {
        conflictHistogram.PrintHotspots();
    }

private:
    size_t size;
    Table* table;
    std::mutex mtx;
    VictimCache victim_;

    uint32_t CompressZZToFingerprint(const TokenZZ& token) const {
        size_t byteLen = NumBytes(token);
        std::vector<unsigned char> bytes(byteLen);
        BytesFromZZ(bytes.data(), token, byteLen);

        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, bytes.data(), byteLen);
        uint8_t out[32];
        blake3_hasher_finalize(&h, out, 32);

        uint64_t raw = *(uint64_t*)(out) ^ *(uint64_t*)(out + 8) ^ *(uint64_t*)(out + 16);
        raw ^= altSeeds.GetSeed(raw % 4);
        return static_cast<uint32_t>(raw & ((1ULL << bits_per_item) - 1));
    }

    std::vector<size_t> AllIndices(uint32_t fp) const {
        std::vector<size_t> indices;
        indices.push_back(FingerprintToIndex(fp));
        for (int round = 0; round < 3; ++round) {
            uint64_t seed = altSeeds.GetSeed(round);
            size_t alt = (XXH3_64bits(&fp, sizeof(fp)) ^ seed) % size;
            if (std::find(indices.begin(), indices.end(), alt) == indices.end()) {
                indices.push_back(alt);
            }
        }
        return indices;
    }

    size_t FingerprintToIndex(uint32_t fp) const {
        return XXH3_64bits(&fp, sizeof(fp)) % size;
    }

    bool Evict(size_t index, uint32_t tag) {
        size_t i = index;
        uint32_t t = tag;
        for (int n = 0; n < kMaxCuckooCount; ++n) {
            uint32_t oldtag, tags[4];
            if (table->Insert(i, t, true, oldtag, tags)) return true;
            t = oldtag;
            i = AllIndices(t)[n % 4];
        }
        victim_ = {i, t, true};
        return false;
    }
};