#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <set>
#include <vector>

#include "triple_vacuum_filter.h"

namespace {

using vlse_original::Token128;

std::vector<Token128> MakeTokens(size_t count) {
    std::mt19937_64 random_engine(0x13198a2e03707344ULL);
    std::set<Token128> unique;
    while (unique.size() < count) {
        const Token128 token =
            (static_cast<Token128>(random_engine()) << 64) | random_engine();
        unique.insert(token);
    }
    return std::vector<Token128>(unique.begin(), unique.end());
}

}  // namespace

int main() {
    constexpr size_t kItems = 4096;
    std::srand(0x1234);  // The upstream implementation uses std::rand for kicks.

    const auto tokens = MakeTokens(kItems);
    vlse_original::TripleVacuumFilter<uint64_t> index(kItems * 2);

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!index.Insert(tokens[i], static_cast<uint64_t>(i + 1))) {
            std::cerr << "insertion failed at item " << i << '\n';
            return 1;
        }
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        const uint64_t* payload = index.Find(tokens[i]);
        if (payload == nullptr || *payload != i + 1) {
            std::cerr << "lookup failed at item " << i << '\n';
            return 1;
        }
    }

    const size_t dummy_fingerprints = index.FillEmptySlots();
    for (size_t i = 0; i < tokens.size(); ++i) {
        const uint64_t* payload = index.Find(tokens[i]);
        if (payload == nullptr || *payload != i + 1) {
            std::cerr << "lookup after padding failed at item " << i << '\n';
            return 1;
        }
    }

    std::cout << "original_vlse_demo: PASS\n"
              << "genuine records: " << index.size() << '\n'
              << "dummy fingerprints: " << dummy_fingerprints << '\n';
    return 0;
}
