#include <initializer_list>
#include <iostream>
#include <stdexcept>
#include "authenticated_results.h"

namespace {
constexpr std::uint64_t kEpoch = 7;
using vlse::protocol::TokenKeyPair;

template <std::size_t D>
vlse::protocol::AeadRecord<D> Record(
    const TokenKeyPair& key, std::uint64_t base, bool valid = true) {
    vlse::protocol::AeadRecord<D> record;
    for (std::size_t j = 0; j < D; ++j) {
        record.components[j] = vlse::EncryptLabel(
            key.key, kEpoch, key.token, static_cast<std::uint32_t>(j),
            valid, valid ? base + j : 0);
    }
    return record;
}

template <std::size_t D>
void Check(const char* name,
           const std::vector<vlse::protocol::AeadRecord<D>>& candidates,
           const TokenKeyPair& key,
           std::initializer_list<std::uint64_t> expected) {
    std::uint64_t attempts = 0;
    const auto result =
        vlse::benchmark::CollectAuthenticatedResults<D, 8>(
            candidates, key, kEpoch, attempts);
    if (attempts != candidates.size() * D ||
        result.size != expected.size() ||
        !std::equal(expected.begin(), expected.end(), result.documents.begin())) {
        throw std::runtime_error(std::string("FAILED: ") + name);
    }
    std::cout << "PASS " << name << " candidates=" << candidates.size()
              << " attempts=" << attempts << " result_size=" << result.size << '\n';
}
}

int main() {
    try {
        TokenKeyPair query{};
        query.token = 123;
        query.key.fill(0x31);
        TokenKeyPair wrong = query;
        wrong.key.fill(0x52);
        // Each key encrypts only one immutable record; later cases reuse it.
        const auto genuine = Record<3>(query, 101);
        const auto unrelated = Record<3>(wrong, 901);
        Check<3>("genuine_first_wrong_last", {genuine, unrelated}, query,
                 {101, 102, 103});
        Check<3>("wrong_first_genuine_last", {unrelated, genuine}, query,
                 {101, 102, 103});
        auto damaged = genuine;
        damaged.components[0].tag[0] ^= 1;
        Check<3>("failed_first_component_valid_later", {damaged}, query,
                 {102, 103});
        Check<3>("duplicate_records_set_union", {genuine, genuine}, query,
                 {101, 102, 103});
        Check<3>("all_authentication_failures", {unrelated}, query, {});
        Check<3>("empty_candidates", {}, query, {});
        TokenKeyPair padding_key = query;
        padding_key.key.fill(0x73);
        const auto padding = Record<3>(padding_key, 0, false);
        Check<3>("authenticated_invalid_padding", {padding}, padding_key, {});
        Check<3>("maximum_candidate_bound",
                 std::vector<vlse::protocol::AeadRecord<3>>(8, genuine), query,
                 {101, 102, 103});
        std::uint64_t attempts = 0;
        bool rejected = false;
        try {
            vlse::benchmark::CollectAuthenticatedResults<3, 8>(
                std::vector<vlse::protocol::AeadRecord<3>>(9, genuine),
                query, kEpoch, attempts);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        if (!rejected || attempts != 0) {
            throw std::runtime_error("candidate bound not enforced");
        }
        std::cout << "PASS oversized_candidates_rejected\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
