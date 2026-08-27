#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <map>
#include <random>
#include <stdexcept>

#include "vacuum.h"

// The upstream header defines several short macros. They are not part of this
// wrapper's public interface.
#undef MAX
#undef MIN
#undef ROUNDUP
#undef ROUNDDOWN
#undef debug
#undef deln
#undef memcle
#undef sqr

namespace vlse_original {

using Token128 = unsigned __int128;

inline std::array<uint64_t, 3> SplitToken(Token128 token) {
    const uint64_t high = static_cast<uint64_t>(token >> 64);
    const uint64_t low = static_cast<uint64_t>(token);
    return {high, low, high ^ low};
}

template <typename Payload>
class TripleVacuumFilter {
public:
    explicit TripleVacuumFilter(
        size_t maximum_items,
        int maximum_kick_steps = 50000) {
        if (maximum_items == 0 ||
            maximum_items > static_cast<size_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument("maximum_items is outside the supported range");
        }
        first_.init(static_cast<int>(maximum_items), 4, maximum_kick_steps);
        second_.init(static_cast<int>(maximum_items), 4, maximum_kick_steps);
        third_.init(static_cast<int>(maximum_items), 4, maximum_kick_steps);
    }

    TripleVacuumFilter(const TripleVacuumFilter&) = delete;
    TripleVacuumFilter& operator=(const TripleVacuumFilter&) = delete;

    bool Insert(Token128 token, const Payload& payload) {
        if (padded_) {
            throw std::logic_error("cannot insert after dummy padding");
        }
        if (payloads_.find(token) != payloads_.end()) {
            return false;
        }

        const auto parts = SplitToken(token);
        // This wrapper uses the upstream insertion API directly. Applications
        // should provision the filters so that insertions do not reach failure.
        if (!first_.insert(parts[0]) || !second_.insert(parts[1]) ||
            !third_.insert(parts[2])) {
            return false;
        }
        payloads_.emplace(token, payload);
        return true;
    }

    const Payload* Find(Token128 token) {
        const auto parts = SplitToken(token);
        if (!first_.lookup(parts[0]) || !second_.lookup(parts[1]) ||
            !third_.lookup(parts[2])) {
            return nullptr;
        }
        const auto iterator = payloads_.find(token);
        return iterator == payloads_.end() ? nullptr : &iterator->second;
    }

    size_t FillEmptySlots(uint64_t seed = 0x243f6a8885a308d3ULL) {
        if (padded_) {
            throw std::logic_error("dummy padding was already applied");
        }
        std::mt19937_64 random_engine(seed);
        const size_t count = FillOne<15>(first_, random_engine) +
                             FillOne<15>(second_, random_engine) +
                             FillOne<13>(third_, random_engine);
        padded_ = true;
        return count;
    }

    size_t size() const { return payloads_.size(); }
    bool padded() const { return padded_; }

private:
    template <int FingerprintBits>
    static size_t FillOne(
        VacuumFilter<uint64_t, FingerprintBits>& filter,
        std::mt19937_64& random_engine) {
        const uint64_t maximum = (uint64_t{1} << FingerprintBits) - 1;
        size_t generated = 0;
        for (long long bucket_index = 0; bucket_index < filter.n;
             ++bucket_index) {
            uint64_t bucket[8]{};
            filter.get_bucket(static_cast<int>(bucket_index), bucket);
            for (int slot = 0; slot < filter.m; ++slot) {
                if (bucket[slot] != 0) {
                    continue;
                }
                bucket[slot] = (random_engine() % maximum) + 1;
                ++generated;
            }
            filter.set_bucket(static_cast<int>(bucket_index), bucket);
        }
        filter.filled_cell += static_cast<int>(generated);
        return generated;
    }

    VacuumFilter<uint64_t, 15> first_;
    VacuumFilter<uint64_t, 15> second_;
    VacuumFilter<uint64_t, 13> third_;
    std::map<Token128, Payload> payloads_;
    bool padded_ = false;
};

}  // namespace vlse_original
