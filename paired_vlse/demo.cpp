#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/rand.h>

#include "aead_label.h"
#include "ntl_oprf.h"
#include "paired_vacuum_filter.h"
#include "protocol_derivation.h"

namespace {
constexpr std::uint64_t kEpoch = 1;
constexpr std::uint32_t kComponent = 0;

std::vector<std::string> MakeKeywords(std::size_t count) {
    std::vector<std::string> keywords;
    keywords.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        keywords.push_back("paired-demo-keyword/" + std::to_string(i));
    }
    return keywords;
}

vlse::oprf::OprfOutput RandomDerivationInput() {
    vlse::oprf::OprfOutput output{};
    if (RAND_bytes(output.data(), output.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return output;
}
}  // namespace

int main() {
    constexpr std::size_t kItems = 256;
    const auto keywords = MakeKeywords(kItems);
    vlse::oprf::NtlOprf oprf{vlse::oprf::SecretKey{}};
    vlse::PairedVacuumFilter<43, vlse::AeadLabel> index(kItems);

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
        const auto candidates = index.QueryAll(derived.token);
        const bool found = std::any_of(
            candidates.begin(), candidates.end(), [&](const vlse::AeadLabel& label) {
                bool valid = false;
                std::uint64_t document = 0;
                return vlse::DecryptLabel(
                           derived.key, kEpoch, derived.token, kComponent, label,
                           &valid, &document) &&
                       valid && document == i + 1;
            });
        if (!found) {
            std::cerr << "authenticated QueryAll failed at item " << i << '\n';
            return 1;
        }
    }

    vlse::protocol::TokenKeyPair pending;
    vlse::AeadLabel pending_label;
    const std::size_t dummy_records = index.FillEmptySlots(
        [&]() {
            pending = vlse::protocol::DeriveTokenAndKey(RandomDerivationInput());
            pending_label = vlse::EncryptLabel(
                pending.key, kEpoch, pending.token, kComponent, false, 0);
            return index.FingerprintForToken(pending.token);
        },
        [&]() { return pending_label; },
        [](std::uint64_t) { return true; });

    if (!index.padded() || index.size() != index.capacity()) {
        std::cerr << "dummy padding did not fill every paired slot\n";
        return 1;
    }
    std::cout << "paired_vlse_demo: PASS\n"
              << "OPRF backend: " << vlse::oprf::PublicParameters::Identifier() << '\n'
              << "TGen OPRFs/query: 1\n"
              << "genuine AES-GCM records: " << kItems << '\n'
              << "authenticated dummy records: " << dummy_records << '\n';
    return 0;
}
