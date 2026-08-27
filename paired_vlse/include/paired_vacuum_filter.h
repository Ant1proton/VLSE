#pragma once

// Long-fingerprint, payload-aligned Vacuum Filter for VLSE.
//
// The placement and semi-sorting ideas follow the MIT-licensed implementation
// by Mingxun Zhou (https://github.com/wuwuz/Vacuum-Filter).  The bucket codec
// below removes the original <=64-bit encoded-bucket limitation by reading and
// writing arbitrary bit fields across machine words.  Fingerprints and payloads
// are always sorted, evicted, committed, and rolled back as one Record.

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#include "hashutil.h"

namespace vlse {

using Token128 = unsigned __int128;

namespace detail {

inline uint64_t RotateLeft64(uint64_t value, unsigned int shift) {
    return (value << shift) | (value >> (64U - shift));
}

inline uint64_t HashToken128(Token128 token, uint64_t seed) {
    const uint64_t hi = static_cast<uint64_t>(token >> 64);
    const uint64_t lo = static_cast<uint64_t>(token);
    return HashUtil::MurmurHash64(
        hi ^ RotateLeft64(lo, 29) ^ HashUtil::MurmurHash64(seed));
}

inline size_t RoundUp(size_t value, size_t alignment) {
    return ((value + alignment - 1) / alignment) * alignment;
}

inline size_t UpperPowerOfTwo(size_t value) {
    size_t result = 1;
    while (result < value) {
        result <<= 1;
    }
    return result;
}

inline double LoadEquationDerivative(double x, double c) {
    return std::log(c) - std::log(x);
}

inline double LoadEquation(double x, double c) {
    return 1 + x * (std::log(c) - std::log(x) + 1) - c;
}

inline double SolveLoadEquation(double c) {
    double x = c + 0.1;
    for (int iteration = 0;
         iteration < 100 && std::abs(LoadEquation(x, c)) > 0.001;
         ++iteration) {
        x -= LoadEquation(x, c) / LoadEquationDerivative(x, c);
    }
    return x;
}

inline double BallsInBinsMaxLoad(double balls, double bins) {
    if (bins <= 1.0) {
        return balls;
    }
    const double c = balls / (bins * std::log(bins));
    if (c < 5.0) {
        return (SolveLoadEquation(c) + 1.0) * std::log(bins);
    }
    return balls / bins + 1.5 * std::sqrt(2.0 * balls / bins * std::log(bins));
}

inline size_t ProperAlternateRange(
    size_t bucket_count,
    int occupancy_class,
    double target_load) {
    constexpr double kSlotsPerBucket = 4.0;
    for (size_t alternate_range = 8; alternate_range < bucket_count;
         alternate_range <<= 1) {
        const double fraction = (4 - occupancy_class) * 0.25;
        if (BallsInBinsMaxLoad(
                fraction * kSlotsPerBucket * target_load * bucket_count,
                static_cast<double>(bucket_count) / alternate_range) <
            0.97 * kSlotsPerBucket * alternate_range) {
            return alternate_range;
        }
    }
    return UpperPowerOfTwo(bucket_count);
}

struct SemiSortCodec {
    std::array<uint16_t, 1U << 16> encode{};
    std::array<uint16_t, 1U << 12> decode{};

    SemiSortCodec() {
        uint16_t index = 0;
        for (int i = 0; i < 16; ++i) {
            for (int j = 0; j < (i == 0 ? 1 : i + 1); ++j) {
                for (int k = 0; k < (j == 0 ? 1 : j + 1); ++k) {
                    for (int l = 0; l < (k == 0 ? 1 : k + 1); ++l) {
                        const uint16_t plain = static_cast<uint16_t>(
                            (i << 12) | (j << 8) | (k << 4) | l);
                        encode[plain] = index;
                        decode[index] = plain;
                        ++index;
                    }
                }
            }
        }
        if (index != 3876) {
            throw std::logic_error("invalid semi-sort codec table");
        }
    }
};

inline const SemiSortCodec& Codec() {
    static const SemiSortCodec codec;
    return codec;
}

inline uint64_t LowMask(size_t width) {
    return width == 64 ? std::numeric_limits<uint64_t>::max()
                       : ((uint64_t{1} << width) - 1);
}

inline uint64_t ReadBits(
    const std::vector<uint8_t>& storage,
    uint64_t bit_position,
    size_t width) {
    assert(width > 0 && width <= 64);
    const size_t byte_position = static_cast<size_t>(bit_position >> 3);
    const size_t bit_offset = static_cast<size_t>(bit_position & 7U);
    unsigned __int128 window = 0;
    std::memcpy(&window, storage.data() + byte_position, sizeof(window));
    window >>= bit_offset;
    return static_cast<uint64_t>(window) & LowMask(width);
}

inline void WriteBits(
    std::vector<uint8_t>& storage,
    uint64_t bit_position,
    size_t width,
    uint64_t value) {
    assert(width > 0 && width <= 64);
    const size_t byte_position = static_cast<size_t>(bit_position >> 3);
    const size_t bit_offset = static_cast<size_t>(bit_position & 7U);
    unsigned __int128 window = 0;
    std::memcpy(&window, storage.data() + byte_position, sizeof(window));
    const unsigned __int128 value_mask =
        width == 64
            ? static_cast<unsigned __int128>(
                  std::numeric_limits<uint64_t>::max())
            : ((static_cast<unsigned __int128>(1) << width) - 1);
    const unsigned __int128 shifted_mask = value_mask << bit_offset;
    window = (window & ~shifted_mask) |
             ((static_cast<unsigned __int128>(value) & value_mask) << bit_offset);
    std::memcpy(storage.data() + byte_position, &window, sizeof(window));
}

}  // namespace detail

template <size_t FingerprintBits, typename Payload>
class PairedVacuumFilter {
    static_assert(FingerprintBits >= 5,
                  "semi-sort encoding needs at least five fingerprint bits");
    static_assert(FingerprintBits <= 64,
                  "fingerprints longer than 64 bits need a wider fp type");
    static_assert(std::is_nothrow_copy_constructible<Payload>::value &&
                      std::is_nothrow_copy_assignable<Payload>::value,
                  "transactional rollback requires a no-throw payload copy");

public:
    static constexpr size_t kSlotsPerBucket = 4;
    static constexpr size_t kEncodedBitsPerBucket =
        kSlotsPerBucket * (FingerprintBits - 1);

    struct Record {
        uint64_t fingerprint = 0;
        Payload payload{};
    };

    struct Statistics {
        uint64_t successful_inserts = 0;
        uint64_t failed_inserts = 0;
        uint64_t eviction_steps = 0;
        uint64_t rollback_count = 0;
        uint64_t maximum_eviction_chain = 0;
    };

    explicit PairedVacuumFilter(
        size_t maximum_items,
        double target_load = 0.95,
        size_t maximum_evictions = 500,
        uint64_t hash_seed = 0x6a09e667f3bcc909ULL,
        uint64_t random_seed = 0xbb67ae8584caa73bULL)
        : maximum_items_(maximum_items),
          target_load_(target_load),
          maximum_evictions_(maximum_evictions),
          hash_seed_(hash_seed),
          random_engine_(random_seed) {
        if (maximum_items == 0) {
            throw std::invalid_argument("maximum_items must be positive");
        }
        if (!(target_load > 0.0 && target_load < 1.0)) {
            throw std::invalid_argument("target_load must be in (0,1)");
        }
        InitializeLayout();
    }

    bool Insert(Token128 token, const Payload& payload) {
        if (padded_) {
            throw std::logic_error("cannot insert genuine records after dummy padding");
        }
        if (filled_slots_ >= capacity()) {
            ++statistics_.failed_inserts;
            return false;
        }

        const KeyMetadata metadata = Metadata(token);
        Bucket first = ReadBucket(metadata.first_bucket);
        Bucket second = metadata.second_bucket == metadata.first_bucket
                            ? first
                            : ReadBucket(metadata.second_bucket);
        const size_t first_count = Occupied(first);
        const size_t second_count = Occupied(second);
        const Record incoming{metadata.fingerprint, payload};

        if (first_count < kSlotsPerBucket || second_count < kSlotsPerBucket) {
            const bool use_first =
                metadata.first_bucket == metadata.second_bucket ||
                first_count <= second_count;
            const size_t destination =
                use_first ? metadata.first_bucket : metadata.second_bucket;
            Bucket bucket = use_first ? first : second;
            bucket[FirstEmpty(bucket)] = incoming;
            WriteBucket(destination, bucket);
            ++filled_slots_;
            ++statistics_.successful_inserts;
            return true;
        }

        std::vector<Snapshot> journal;
        journal.reserve(maximum_evictions_ + 2);
        Record carried = incoming;
        size_t current_bucket =
            (random_engine_() & 1U) ? metadata.first_bucket : metadata.second_bucket;
        size_t chain_length = 0;

        Bucket current = ReadBucket(current_bucket);
        const size_t selected_slot =
            static_cast<size_t>(random_engine_() % kSlotsPerBucket);
        std::swap(carried, current[selected_slot]);
        JournalWrite(current_bucket, current, journal);
        current_bucket = Alternate(current_bucket, carried.fingerprint);

        for (; chain_length < maximum_evictions_; ++chain_length) {
            Bucket bucket = ReadBucket(current_bucket);
            if (Occupied(bucket) < kSlotsPerBucket) {
                bucket[FirstEmpty(bucket)] = carried;
                JournalWrite(current_bucket, bucket, journal);
                ++filled_slots_;
                ++statistics_.successful_inserts;
                statistics_.eviction_steps += chain_length + 1;
                statistics_.maximum_eviction_chain = std::max<uint64_t>(
                    statistics_.maximum_eviction_chain, chain_length + 1);
                return true;
            }

            bool shortcut_succeeded = false;
            for (size_t slot = 0; slot < kSlotsPerBucket; ++slot) {
                const size_t next_bucket =
                    Alternate(current_bucket, bucket[slot].fingerprint);
                if (next_bucket == current_bucket) {
                    continue;
                }
                Bucket next = ReadBucket(next_bucket);
                if (Occupied(next) == kSlotsPerBucket) {
                    continue;
                }

                const Record moved = bucket[slot];
                bucket[slot] = carried;
                next[FirstEmpty(next)] = moved;
                JournalWrite(current_bucket, bucket, journal);
                JournalWrite(next_bucket, next, journal);
                ++filled_slots_;
                ++statistics_.successful_inserts;
                statistics_.eviction_steps += chain_length + 1;
                statistics_.maximum_eviction_chain = std::max<uint64_t>(
                    statistics_.maximum_eviction_chain, chain_length + 1);
                shortcut_succeeded = true;
                break;
            }
            if (shortcut_succeeded) {
                return true;
            }

            const size_t eviction_slot =
                static_cast<size_t>(random_engine_() % kSlotsPerBucket);
            std::swap(carried, bucket[eviction_slot]);
            JournalWrite(current_bucket, bucket, journal);
            current_bucket = Alternate(current_bucket, carried.fingerprint);
        }

        RollBack(journal);
        ++statistics_.failed_inserts;
        ++statistics_.rollback_count;
        statistics_.eviction_steps += chain_length;
        statistics_.maximum_eviction_chain = std::max<uint64_t>(
            statistics_.maximum_eviction_chain, chain_length);
        return false;
    }

    size_t QueryAll(Token128 token, Payload* output, size_t output_capacity) const {
        const KeyMetadata metadata = Metadata(token);
        size_t matches = 0;
        matches += CollectMatches(
            metadata.first_bucket,
            metadata.fingerprint,
            output,
            output_capacity,
            matches);
        if (metadata.second_bucket != metadata.first_bucket) {
            matches += CollectMatches(
                metadata.second_bucket,
                metadata.fingerprint,
                output,
                output_capacity,
                matches);
        }
        return matches;
    }

    std::vector<Payload> QueryAll(Token128 token) const {
        std::array<Payload, 2 * kSlotsPerBucket> matches{};
        const size_t count = QueryAll(token, matches.data(), matches.size());
        return std::vector<Payload>(matches.begin(), matches.begin() + count);
    }

    bool Contains(Token128 token) const {
        return QueryAll(token, nullptr, 0) != 0;
    }

    template <typename FingerprintGenerator, typename PayloadGenerator,
              typename FingerprintPredicate>
    size_t FillEmptySlots(
        FingerprintGenerator&& fingerprint_generator,
        PayloadGenerator&& payload_generator,
        FingerprintPredicate&& fingerprint_allowed) {
        if (padded_) {
            throw std::logic_error("dummy padding was already applied");
        }
        size_t generated = 0;
        std::vector<Snapshot> journal;
        journal.reserve(bucket_count_);
        try {
            for (size_t bucket_index = 0; bucket_index < bucket_count_;
                 ++bucket_index) {
                Bucket bucket = ReadBucket(bucket_index);
                bool changed = false;
                for (Record& record : bucket) {
                    if (record.fingerprint != 0) {
                        continue;
                    }
                    uint64_t candidate = 0;
                    do {
                        candidate = fingerprint_generator() & FingerprintMask();
                    } while (candidate == 0 || !fingerprint_allowed(candidate));
                    record.fingerprint = candidate;
                    record.payload = payload_generator();
                    ++generated;
                    changed = true;
                }
                if (changed) {
                    JournalWrite(bucket_index, bucket, journal);
                }
            }
        } catch (...) {
            RollBack(journal);
            throw;
        }
        filled_slots_ += generated;
        padded_ = true;
        return generated;
    }

    uint64_t FingerprintForToken(Token128 token) const {
        return Metadata(token).fingerprint;
    }

    std::pair<size_t, size_t> CandidateBuckets(Token128 token) const {
        const KeyMetadata metadata = Metadata(token);
        return {metadata.first_bucket, metadata.second_bucket};
    }

    size_t bucket_count() const { return bucket_count_; }
    size_t capacity() const { return bucket_count_ * kSlotsPerBucket; }
    size_t size() const { return filled_slots_; }
    double load_factor() const {
        return capacity() == 0 ? 0.0
                               : static_cast<double>(filled_slots_) / capacity();
    }
    size_t logical_fingerprint_bytes() const { return logical_fingerprint_bytes_; }
    size_t payload_bytes() const { return payloads_.size() * sizeof(Payload); }
    size_t total_logical_bytes() const {
        return logical_fingerprint_bytes() + payload_bytes();
    }
    bool padded() const { return padded_; }
    const Statistics& statistics() const { return statistics_; }

private:
    using Bucket = std::array<Record, kSlotsPerBucket>;

    struct KeyMetadata {
        uint64_t fingerprint;
        size_t first_bucket;
        size_t second_bucket;
    };

    struct Snapshot {
        size_t bucket_index;
        Bucket bucket;
    };

    static uint64_t FingerprintMask() {
        return std::numeric_limits<uint64_t>::max() >> (64 - FingerprintBits);
    }

    void InitializeLayout() {
        size_t requested_buckets = static_cast<size_t>(std::ceil(
            maximum_items_ / (target_load_ * kSlotsPerBucket)));
        requested_buckets = std::max<size_t>(1, requested_buckets);

        if (requested_buckets < 10000) {
            const size_t segment = requested_buckets < 256
                                       ? detail::UpperPowerOfTwo(requested_buckets)
                                       : detail::UpperPowerOfTwo(
                                             (requested_buckets + 3) / 4);
            bucket_count_ = detail::RoundUp(requested_buckets, segment);
            alternate_masks_.fill(segment - 1);
        } else {
            const size_t base_range = detail::ProperAlternateRange(
                requested_buckets, 0, target_load_);
            bucket_count_ = detail::RoundUp(requested_buckets, base_range);
            alternate_masks_[0] = std::max<size_t>(base_range - 1, 1024);
            for (int i = 1; i < 4; ++i) {
                alternate_masks_[i] = detail::ProperAlternateRange(
                    bucket_count_, i, target_load_) - 1;
            }
            alternate_masks_[3] = (alternate_masks_[3] + 1) * 2 - 1;
        }

        const uint64_t total_bits =
            static_cast<uint64_t>(bucket_count_) * kEncodedBitsPerBucket;
        logical_fingerprint_bytes_ = static_cast<size_t>((total_bits + 7) / 8);
        // ReadBits/WriteBits copy a 16-byte window.  Guard bytes keep the last
        // unaligned bucket access within the allocated vector.
        fingerprint_storage_.assign(logical_fingerprint_bytes_ + 16, 0);
        payloads_.resize(capacity());
    }

    KeyMetadata Metadata(Token128 token) const {
        const uint64_t element = detail::HashToken128(token, hash_seed_);
        uint64_t fingerprint_state =
            HashUtil::MurmurHash64(element ^ 0x192837319273ULL);
        uint64_t fingerprint = fingerprint_state & FingerprintMask();
        // Zero is the empty-slot sentinel.  Rehash instead of mapping zero to
        // one, which would give fingerprint one twice the intended mass.
        // In the random-oracle model this samples uniformly from the
        // 2^FingerprintBits - 1 nonzero values.
        while (fingerprint == 0) {
            fingerprint_state = HashUtil::MurmurHash64(
                fingerprint_state ^ 0x9e3779b97f4a7c15ULL);
            fingerprint = fingerprint_state & FingerprintMask();
        }
        const size_t first = static_cast<size_t>(element % bucket_count_);
        const size_t second = Alternate(first, fingerprint);
        return {fingerprint, first, second};
    }

    size_t Alternate(size_t position, uint64_t fingerprint) const {
        const uint32_t fingerprint_hash =
            static_cast<uint32_t>(fingerprint) * 0x5bd1e995U;
        const size_t mask = alternate_masks_[fingerprint & 3U];
        const size_t alternate = position ^ (fingerprint_hash & mask);
        assert(alternate < bucket_count_);
        return alternate;
    }

    static size_t Occupied(const Bucket& bucket) {
        size_t count = 0;
        for (const Record& record : bucket) {
            count += record.fingerprint != 0;
        }
        return count;
    }

    static size_t FirstEmpty(const Bucket& bucket) {
        for (size_t i = 0; i < bucket.size(); ++i) {
            if (bucket[i].fingerprint == 0) {
                return i;
            }
        }
        throw std::logic_error("bucket is full");
    }

    Bucket ReadBucket(size_t position) const {
        const size_t low_width = FingerprintBits - 4;
        const uint64_t start =
            static_cast<uint64_t>(position) * kEncodedBitsPerBucket;
        const uint16_t encoded_high = static_cast<uint16_t>(detail::ReadBits(
            fingerprint_storage_, start + 4 * low_width, 12));
        const uint16_t decoded_high = detail::Codec().decode[encoded_high];

        Bucket bucket{};
        for (size_t slot = 0; slot < kSlotsPerBucket; ++slot) {
            const size_t reverse_slot = kSlotsPerBucket - 1 - slot;
            const uint64_t low = detail::ReadBits(
                fingerprint_storage_, start + reverse_slot * low_width, low_width);
            const uint64_t high =
                (decoded_high >> (reverse_slot * 4)) & 0xFULL;
            bucket[slot].fingerprint = low | (high << low_width);
            bucket[slot].payload = payloads_[position * kSlotsPerBucket + slot];
        }
        return bucket;
    }

    void WriteBucket(size_t position, Bucket bucket) {
        std::stable_sort(
            bucket.begin(),
            bucket.end(),
            [](const Record& left, const Record& right) {
                return left.fingerprint > right.fingerprint;
            });

        const size_t low_width = FingerprintBits - 4;
        const uint64_t low_mask = detail::LowMask(low_width);
        const uint64_t start =
            static_cast<uint64_t>(position) * kEncodedBitsPerBucket;
        uint16_t high_plain = 0;

        for (size_t slot = 0; slot < kSlotsPerBucket; ++slot) {
            const size_t reverse_slot = kSlotsPerBucket - 1 - slot;
            detail::WriteBits(
                fingerprint_storage_,
                start + reverse_slot * low_width,
                low_width,
                bucket[slot].fingerprint & low_mask);
            high_plain |= static_cast<uint16_t>(
                ((bucket[slot].fingerprint >> low_width) & 0xFULL)
                << (reverse_slot * 4));
            payloads_[position * kSlotsPerBucket + slot] = bucket[slot].payload;
        }

        detail::WriteBits(
            fingerprint_storage_,
            start + 4 * low_width,
            12,
            detail::Codec().encode[high_plain]);
    }

    void JournalWrite(
        size_t position,
        const Bucket& bucket,
        std::vector<Snapshot>& journal) {
        journal.push_back({position, ReadBucket(position)});
        WriteBucket(position, bucket);
    }

    void RollBack(const std::vector<Snapshot>& journal) {
        for (auto iterator = journal.rbegin(); iterator != journal.rend(); ++iterator) {
            WriteBucket(iterator->bucket_index, iterator->bucket);
        }
    }

    size_t CollectMatches(
        size_t position,
        uint64_t fingerprint,
        Payload* output,
        size_t output_capacity,
        size_t output_offset) const {
        const Bucket bucket = ReadBucket(position);
        size_t count = 0;
        for (const Record& record : bucket) {
            if (record.fingerprint != fingerprint) {
                continue;
            }
            if (output != nullptr && output_offset + count < output_capacity) {
                output[output_offset + count] = record.payload;
            }
            ++count;
        }
        return count;
    }

    size_t maximum_items_;
    double target_load_;
    size_t maximum_evictions_;
    uint64_t hash_seed_;
    std::mt19937_64 random_engine_;
    size_t bucket_count_ = 0;
    std::array<size_t, 4> alternate_masks_{};
    size_t logical_fingerprint_bytes_ = 0;
    std::vector<uint8_t> fingerprint_storage_;
    std::vector<Payload> payloads_;
    size_t filled_slots_ = 0;
    bool padded_ = false;
    Statistics statistics_{};
};

}  // namespace vlse
