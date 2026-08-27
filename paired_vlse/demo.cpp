#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <set>
#include <vector>

#include "aead_label.h"
#include "paired_vacuum_filter.h"

namespace {

constexpr uint64_t kEpoch = 1;
constexpr uint32_t kComponent = 0;

std::vector<vlse::Token128> MakeTokens(size_t count) {
    std::mt19937_64 random_engine(0xa4093822299f31d0ULL);
    std::set<vlse::Token128> unique;
    while (unique.size() < count) {
        const vlse::Token128 token =
            (static_cast<vlse::Token128>(random_engine()) << 64) |
            random_engine();
        unique.insert(token);
    }
    return std::vector<vlse::Token128>(unique.begin(), unique.end());
}

bool FindDocument(
    const vlse::PairedVacuumFilter<43, vlse::AeadLabel>& filter,
    const vlse::AeadKey128& key,
    vlse::Token128 token,
    uint64_t expected_document) {
    const auto candidates = filter.QueryAll(token);
    return std::any_of(
        candidates.begin(), candidates.end(), [&](const vlse::AeadLabel& label) {
            bool valid = false;
            uint64_t document = 0;
            return vlse::DecryptLabel(
                       key, kEpoch, token, kComponent, label, &valid, &document) &&
                   valid && document == expected_document;
        });
}

}  // namespace

int main() {
    constexpr size_t kItems = 4096;
    const auto tokens = MakeTokens(kItems);

    vlse::AeadKey128 key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 17 + 3);
    }

    vlse::PairedVacuumFilter<43, vlse::AeadLabel> index(kItems);
    for (size_t i = 0; i < tokens.size(); ++i) {
        const auto label = vlse::EncryptLabel(
            key, kEpoch, tokens[i], kComponent, true, i + 1);
        if (!index.Insert(tokens[i], label)) {
            std::cerr << "insertion failed at item " << i << '\n';
            return 1;
        }
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!FindDocument(index, key, tokens[i], i + 1)) {
            std::cerr << "lookup failed at item " << i << '\n';
            return 1;
        }
    }

    std::mt19937_64 dummy_random(0x082efa98ec4e6c89ULL);
    const size_t dummy_records = index.FillEmptySlots(
        [&]() { return dummy_random(); },
        []() { return vlse::RandomDummyLabel(); },
        [](uint64_t) { return true; });

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!FindDocument(index, key, tokens[i], i + 1)) {
            std::cerr << "lookup after padding failed at item " << i << '\n';
            return 1;
        }
    }

    if (!index.padded() || index.size() != index.capacity()) {
        std::cerr << "dummy padding did not fill every slot\n";
        return 1;
    }

    std::cout << "paired_vlse_demo: PASS\n"
              << "genuine records: " << tokens.size() << '\n'
              << "dummy records: " << dummy_records << '\n';
    return 0;
}
