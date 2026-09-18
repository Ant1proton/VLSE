#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "aead_label.h"
#include "paired_vacuum_filter.h"

namespace {

vlse::AeadKey128 KeyFor(std::size_t index) {
    vlse::AeadKey128 key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((index * 29 + i * 17 + 3) & 0xff);
    }
    return key;
}

}  // namespace

int main() {
    constexpr std::size_t kItems = 256;
    constexpr std::uint64_t kEpoch = 9;
    vlse::PairedVacuumFilter<5, vlse::AeadLabel> index(kItems);
    std::vector<vlse::Token128> tokens;
    tokens.reserve(kItems);

    for (std::size_t i = 0; i < kItems; ++i) {
        const vlse::Token128 token =
            (static_cast<vlse::Token128>(i + 1) << 64) |
            static_cast<std::uint64_t>(i * 0x9e3779b97f4a7c15ULL + 7);
        tokens.push_back(token);
        const auto label = vlse::EncryptLabel(
            KeyFor(i), kEpoch, token, 0, true, i + 1);
        if (!index.Insert(token, label)) {
            std::cerr << "collision test insertion failed\n";
            return 1;
        }
    }

    bool observed_multiple_candidates = false;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const auto candidates = index.QueryAll(tokens[i]);
        observed_multiple_candidates |= candidates.size() > 1;
        std::size_t accepted = 0;
        for (const auto& candidate : candidates) {
            bool valid = false;
            std::uint64_t document = 0;
            if (vlse::DecryptLabel(
                    KeyFor(i), kEpoch, tokens[i], 0, candidate,
                    &valid, &document) &&
                valid && document == i + 1) {
                ++accepted;
            }
        }
        if (accepted != 1) {
            std::cerr << "AEAD did not select exactly one collision candidate\n";
            return 1;
        }
    }

    if (!observed_multiple_candidates) {
        std::cerr << "test did not exercise a genuine fingerprint collision\n";
        return 1;
    }
    std::cout << "paired_collision_test: PASS\n";
    return 0;
}
