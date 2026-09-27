#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "protocol_derivation.h"
#include "protocol_record.h"

namespace vlse::benchmark {

template <std::size_t DMax, std::size_t MaxCandidates>
struct AuthenticatedResults {
    // The prefix [0, size) is the sorted, duplicate-free result set.
    std::array<std::uint64_t, DMax * MaxCandidates> documents{};
    std::size_t size = 0;
};

// No expected answer is available to the protocol execution.
// The caller includes this entire function in search/decrypt timing.
template <std::size_t DMax, std::size_t MaxCandidates>
inline AuthenticatedResults<DMax, MaxCandidates> CollectAuthenticatedResults(
    const std::vector<protocol::AeadRecord<DMax>>& candidates,
    const protocol::TokenKeyPair& derived,
    std::uint64_t epoch,
    std::uint64_t& component_attempts) {
    if (candidates.size() > MaxCandidates) {
        throw std::runtime_error("candidate bound exceeded");
    }
    AuthenticatedResults<DMax, MaxCandidates> results;
    for (const auto& candidate : candidates) {
        for (std::size_t j = 0; j < DMax; ++j) {
            ++component_attempts;
            bool valid = false;
            std::uint64_t document = 0;
            const bool decoded = DecryptLabel(
                derived.key, epoch, derived.token,
                static_cast<std::uint32_t>(j), candidate.components[j],
                &valid, &document);
            if (decoded && valid) {
                results.documents[results.size++] = document;
            }
        }
    }
    if (results.size > 1) {
        auto end = results.documents.begin() + results.size;
        std::sort(results.documents.begin(), end);
        end = std::unique(results.documents.begin(), end);
        results.size = static_cast<std::size_t>(end - results.documents.begin());
    }
    return results;
}

}  // namespace vlse::benchmark
