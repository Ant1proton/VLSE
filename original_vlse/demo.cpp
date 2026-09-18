#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "aead_label.h"
#include "ntl_oprf.h"
#include "protocol_derivation.h"
#include "triple_vacuum_filter.h"

namespace {
constexpr std::uint64_t kEpoch = 1;
constexpr std::uint32_t kComponent = 0;

std::vector<std::string> MakeKeywords(std::size_t count) {
    std::vector<std::string> keywords;
    keywords.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        keywords.push_back("original-demo-keyword/" + std::to_string(i));
    }
    return keywords;
}
}  // namespace

int main() {
    constexpr std::size_t kItems = 256;
    std::srand(0x1234);
    const auto keywords = MakeKeywords(kItems);
    vlse::oprf::NtlOprf oprf{vlse::oprf::SecretKey{}};
    vlse_original::TripleVacuumFilter<vlse::AeadLabel> index(kItems * 2);

    for (std::size_t i = 0; i < keywords.size(); ++i) {
        const auto derived = vlse::protocol::DeriveTokenAndKey(
            oprf.DirectEvaluate(keywords[i]));
        const auto label = vlse::EncryptLabel(
            derived.key, kEpoch, derived.token, kComponent, true, i + 1);
        if (!index.Insert(derived.token, label)) {
            std::cerr << "insertion failed at item " << i << '\n';
            return 1;
        }
    }

    auto blinds = oprf.PrepareBlindPool(keywords.size());
    for (std::size_t i = 0; i < keywords.size(); ++i) {
        const auto derived = vlse::protocol::DeriveTokenAndKey(
            oprf.EvaluatePrepared(keywords[i], blinds[i]));
        const vlse::AeadLabel* label = index.Find(derived.token);
        bool valid = false;
        std::uint64_t document = 0;
        if (label == nullptr ||
            !vlse::DecryptLabel(
                derived.key, kEpoch, derived.token, kComponent, *label,
                &valid, &document) ||
            !valid || document != i + 1) {
            std::cerr << "authenticated lookup failed at item " << i << '\n';
            return 1;
        }
    }

    const std::size_t dummy_fingerprints = index.FillEmptySlots();
    std::cout << "original_vlse_demo: PASS\n"
              << "OPRF backend: " << vlse::oprf::PublicParameters::Identifier() << '\n'
              << "TGen OPRFs/query: 1\n"
              << "genuine AES-GCM records: " << index.size() << '\n'
              << "dummy fingerprints: " << dummy_fingerprints << '\n';
    return 0;
}
