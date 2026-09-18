#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/rand.h>

#include "aead_label.h"
#include "ntl_oprf.h"
#include "paired_vacuum_filter.h"
#include "protocol_derivation.h"
#include "protocol_record.h"
#include "triple_vacuum_filter.h"

namespace {

using Clock = std::chrono::steady_clock;
using vlse::oprf::NtlOprf;
using vlse::oprf::OprfOutput;
using vlse::oprf::SecretKey;
using vlse::protocol::TokenKeyPair;

constexpr std::array<std::size_t, 5> kQueryCheckpoints{
    200, 400, 600, 800, 1000};

struct Options {
    std::string layout = "paired";
    std::size_t keywords = 4096;
    std::size_t queries = 40;
    std::size_t dmax = 1;
    std::uint64_t seed = 1;
};

std::size_t ParseSize(const char* text, const char* name) {
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (end == text || *end != '\0' || value == 0) {
        throw std::invalid_argument(std::string("invalid ") + name);
    }
    return static_cast<std::size_t>(value);
}

Options ParseOptions(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        auto consume = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                throw std::invalid_argument(std::string("missing value for ") + name);
            }
            return argv[++i];
        };
        if (argument == "--layout") {
            options.layout = consume("--layout");
        } else if (argument == "--keywords") {
            options.keywords = ParseSize(consume("--keywords"), "--keywords");
        } else if (argument == "--queries") {
            options.queries = ParseSize(consume("--queries"), "--queries");
        } else if (argument == "--dmax") {
            options.dmax = ParseSize(consume("--dmax"), "--dmax");
        } else if (argument == "--seed") {
            options.seed = ParseSize(consume("--seed"), "--seed");
        } else if (argument == "--help") {
            std::cout << "Usage: vlse_protocol_benchmark [--layout original|paired] "
                         "[--keywords N] [--queries Q] [--dmax 1|5|10|15|20] "
                         "[--seed S]\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
    }
    if (options.layout != "original" && options.layout != "paired") {
        throw std::invalid_argument("--layout must be original or paired");
    }
    if (options.queries > options.keywords) {
        throw std::invalid_argument("queries cannot exceed keywords");
    }
    return options;
}

std::vector<std::string> MakeKeywords(std::size_t count, std::uint64_t seed) {
    std::vector<std::string> result;
    result.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        result.push_back(
            "keyword/" + std::to_string(seed) + "/" + std::to_string(i));
    }
    return result;
}

double Milliseconds(Clock::duration duration) {
    return std::chrono::duration<double, std::milli>(duration).count();
}

OprfOutput RandomOprfShape() {
    OprfOutput output{};
    if (RAND_bytes(output.data(), output.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed for dummy derivation seed");
    }
    return output;
}

template <std::size_t DMax>
vlse::protocol::AeadRecord<DMax> MakeRecord(
    const TokenKeyPair& derived,
    std::uint64_t epoch,
    std::uint64_t document_base,
    bool valid) {
    vlse::protocol::AeadRecord<DMax> record;
    const vlse::AeadKey128 key = derived.key;
    for (std::size_t j = 0; j < DMax; ++j) {
        record.components[j] = vlse::EncryptLabel(
            key,
            epoch,
            derived.token,
            static_cast<std::uint32_t>(j),
            valid,
            valid ? document_base + j : 0);
    }
    return record;
}

template <std::size_t DMax>
bool DecryptExpected(
    const vlse::protocol::AeadRecord<DMax>& record,
    const TokenKeyPair& derived,
    std::uint64_t epoch,
    std::uint64_t expected_base,
    std::uint64_t* component_attempts = nullptr) {
    const vlse::AeadKey128 key = derived.key;
    for (std::size_t j = 0; j < DMax; ++j) {
        if (component_attempts != nullptr) {
            ++(*component_attempts);
        }
        bool valid = false;
        std::uint64_t document = 0;
        if (!vlse::DecryptLabel(
                key,
                epoch,
                derived.token,
                static_cast<std::uint32_t>(j),
                record.components[j],
                &valid,
                &document) ||
            !valid || document != expected_base + j) {
            return false;
        }
    }
    return true;
}

struct Metrics {
    double blind_precomputation_ms = 0;
    double setup_ms = 0;
    double setup_genuine_ms = 0;
    double setup_insert_ms = 0;
    double setup_dummy_ms = 0;
    double tgen_ms = 0;
    double search_decrypt_ms = 0;
    std::size_t serialized_bytes = 0;
    std::size_t communication_bytes = 0;
    std::size_t dummy_records = 0;
    std::size_t capacity_slots = 0;
    std::size_t setup_attempts = 0;
    std::size_t failed_setup_attempts = 0;
    std::uint64_t successful_inserts = 0;
    std::uint64_t failed_inserts = 0;
    std::uint64_t eviction_steps = 0;
    std::uint64_t rollback_count = 0;
    std::uint64_t maximum_eviction_chain = 0;
    std::uint64_t query_successes = 0;
    std::uint64_t candidate_records_total = 0;
    std::uint64_t candidate_records_max = 0;
    std::uint64_t decrypt_component_attempts = 0;
    std::array<double, kQueryCheckpoints.size()> online_checkpoint_ms{
        -1, -1, -1, -1, -1};
};

template <std::size_t DMax>
Metrics RunPaired(const Options& options) {
    const std::uint64_t epoch = options.seed;
    const auto keywords = MakeKeywords(options.keywords, options.seed);
    NtlOprf oprf{SecretKey{}};
    using Record = vlse::protocol::AeadRecord<DMax>;

    const auto pre_start = Clock::now();
    auto blind_pool = oprf.PrepareBlindPool(options.queries);
    const auto pre_end = Clock::now();

    const auto setup_start = Clock::now();
    std::vector<std::pair<TokenKeyPair, Record>> genuine_records;
    genuine_records.reserve(keywords.size());
    for (std::size_t i = 0; i < keywords.size(); ++i) {
        const TokenKeyPair derived = vlse::protocol::DeriveTokenAndKey(
            oprf.DirectEvaluate(keywords[i]));
        genuine_records.emplace_back(
            derived, MakeRecord<DMax>(derived, epoch, i * DMax + 1, true));
    }
    const auto genuine_end = Clock::now();

    using Index = vlse::PairedVacuumFilter<43, Record>;
    std::unique_ptr<Index> index;
    std::vector<std::size_t> order(options.keywords);
    std::iota(order.begin(), order.end(), 0);
    std::size_t setup_attempts = 0;
    std::size_t failed_setup_attempts = 0;
    std::uint64_t successful_inserts = 0;
    std::uint64_t failed_inserts = 0;
    std::uint64_t eviction_steps = 0;
    std::uint64_t rollback_count = 0;
    std::uint64_t maximum_eviction_chain = 0;
    for (std::size_t attempt = 0; attempt < 4 && !index; ++attempt) {
        ++setup_attempts;
        const std::size_t scheduled_items =
            options.keywords + (options.keywords * attempt) / 20;
        auto candidate = std::make_unique<Index>(
            scheduled_items,
            0.95,
            500,
            options.seed ^ (0x6a09e667f3bcc909ULL + attempt),
            options.seed ^ (0xbb67ae8584caa73bULL + attempt));
        std::mt19937_64 permutation_random(
            options.seed ^ (0x3c6ef372fe94f82bULL + attempt));
        std::shuffle(order.begin(), order.end(), permutation_random);
        bool success = true;
        for (const std::size_t record_index : order) {
            const auto& entry = genuine_records[record_index];
            if (!candidate->Insert(entry.first.token, entry.second)) {
                success = false;
                break;
            }
        }
        const auto& statistics = candidate->statistics();
        successful_inserts += statistics.successful_inserts;
        failed_inserts += statistics.failed_inserts;
        eviction_steps += statistics.eviction_steps;
        rollback_count += statistics.rollback_count;
        maximum_eviction_chain = std::max(
            maximum_eviction_chain, statistics.maximum_eviction_chain);
        if (success) {
            index = std::move(candidate);
        } else {
            ++failed_setup_attempts;
        }
    }
    if (!index) {
        throw std::runtime_error("paired bounded Setup exhausted all retries");
    }
    const auto insert_end = Clock::now();

    TokenKeyPair pending_dummy;
    Record pending_record;
    const std::size_t dummies = index->FillEmptySlots(
        [&]() {
            pending_dummy = vlse::protocol::DeriveTokenAndKey(RandomOprfShape());
            pending_record = MakeRecord<DMax>(pending_dummy, epoch, 0, false);
            return index->FingerprintForToken(pending_dummy.token);
        },
        [&]() { return pending_record; },
        [](std::uint64_t) { return true; });
    const auto setup_end = Clock::now();

    double tgen_ms = 0;
    double search_ms = 0;
    std::uint64_t query_successes = 0;
    std::uint64_t candidate_records_total = 0;
    std::uint64_t candidate_records_max = 0;
    std::uint64_t decrypt_component_attempts = 0;
    std::array<double, kQueryCheckpoints.size()> online_checkpoint_ms{
        -1, -1, -1, -1, -1};
    for (std::size_t i = 0; i < options.queries; ++i) {
        const auto tgen_start = Clock::now();
        const TokenKeyPair derived = vlse::protocol::DeriveTokenAndKey(
            oprf.EvaluatePrepared(keywords[i], blind_pool[i]));
        const auto tgen_end = Clock::now();

        const auto search_start = Clock::now();
        const auto candidates = index->QueryAll(derived.token);
        candidate_records_total += candidates.size();
        candidate_records_max = std::max<std::uint64_t>(
            candidate_records_max, candidates.size());
        bool found = false;
        for (const Record& candidate : candidates) {
            if (DecryptExpected<DMax>(
                    candidate,
                    derived,
                    epoch,
                    i * DMax + 1,
                    &decrypt_component_attempts)) {
                found = true;
                break;
            }
        }
        const auto search_end = Clock::now();
        if (!found) {
            throw std::runtime_error("paired authenticated lookup failed");
        }
        ++query_successes;
        tgen_ms += Milliseconds(tgen_end - tgen_start);
        search_ms += Milliseconds(search_end - search_start);
        for (std::size_t checkpoint = 0;
             checkpoint < kQueryCheckpoints.size(); ++checkpoint) {
            if (i + 1 == kQueryCheckpoints[checkpoint]) {
                online_checkpoint_ms[checkpoint] = tgen_ms + search_ms;
                break;
            }
        }
    }

    Metrics metrics;
    metrics.blind_precomputation_ms = Milliseconds(pre_end - pre_start);
    metrics.setup_ms = Milliseconds(setup_end - setup_start);
    metrics.setup_genuine_ms = Milliseconds(genuine_end - setup_start);
    metrics.setup_insert_ms = Milliseconds(insert_end - genuine_end);
    metrics.setup_dummy_ms = Milliseconds(setup_end - insert_end);
    metrics.tgen_ms = tgen_ms;
    metrics.search_decrypt_ms = search_ms;
    metrics.serialized_bytes = index->logical_fingerprint_bytes() +
        index->capacity() * vlse::protocol::SerializedRecordBytes<DMax>();
    metrics.communication_bytes = index->total_logical_bytes() +
        options.queries * NtlOprf::CommunicationBytesPerEvaluation();
    metrics.dummy_records = dummies;
    metrics.capacity_slots = index->capacity();
    metrics.setup_attempts = setup_attempts;
    metrics.failed_setup_attempts = failed_setup_attempts;
    metrics.successful_inserts = successful_inserts;
    metrics.failed_inserts = failed_inserts;
    metrics.eviction_steps = eviction_steps;
    metrics.rollback_count = rollback_count;
    metrics.maximum_eviction_chain = maximum_eviction_chain;
    metrics.query_successes = query_successes;
    metrics.candidate_records_total = candidate_records_total;
    metrics.candidate_records_max = candidate_records_max;
    metrics.decrypt_component_attempts = decrypt_component_attempts;
    metrics.online_checkpoint_ms = online_checkpoint_ms;
    return metrics;
}

template <std::size_t DMax>
Metrics RunOriginal(const Options& options) {
    const std::uint64_t epoch = options.seed;
    const auto keywords = MakeKeywords(options.keywords, options.seed);
    NtlOprf oprf{SecretKey{}};
    using Record = vlse::protocol::AeadRecord<DMax>;

    const auto pre_start = Clock::now();
    auto blind_pool = oprf.PrepareBlindPool(options.queries);
    const auto pre_end = Clock::now();

    const auto setup_start = Clock::now();
    // This keeps the repository's historical three-filter wrapper and map.
    // It is a legacy implementation comparator, not the revised paired scheme.
    vlse_original::TripleVacuumFilter<Record> index(options.keywords * 2);
    for (std::size_t i = 0; i < keywords.size(); ++i) {
        const TokenKeyPair derived = vlse::protocol::DeriveTokenAndKey(
            oprf.DirectEvaluate(keywords[i]));
        const Record record = MakeRecord<DMax>(derived, epoch, i * DMax + 1, true);
        if (!index.Insert(derived.token, record)) {
            throw std::runtime_error("original insertion failed at item " +
                                     std::to_string(i));
        }
    }
    const auto genuine_end = Clock::now();
    const std::size_t dummies = index.FillEmptySlots(options.seed);
    const auto setup_end = Clock::now();

    double tgen_ms = 0;
    double search_ms = 0;
    std::uint64_t query_successes = 0;
    std::uint64_t decrypt_component_attempts = 0;
    for (std::size_t i = 0; i < options.queries; ++i) {
        const auto tgen_start = Clock::now();
        const TokenKeyPair derived = vlse::protocol::DeriveTokenAndKey(
            oprf.EvaluatePrepared(keywords[i], blind_pool[i]));
        const auto tgen_end = Clock::now();

        const auto search_start = Clock::now();
        const Record* record = index.Find(derived.token);
        const bool found = record != nullptr && DecryptExpected<DMax>(
            *record,
            derived,
            epoch,
            i * DMax + 1,
            &decrypt_component_attempts);
        const auto search_end = Clock::now();
        if (!found) {
            throw std::runtime_error("original authenticated lookup failed");
        }
        ++query_successes;
        tgen_ms += Milliseconds(tgen_end - tgen_start);
        search_ms += Milliseconds(search_end - search_start);
    }

    Metrics metrics;
    metrics.blind_precomputation_ms = Milliseconds(pre_end - pre_start);
    metrics.setup_ms = Milliseconds(setup_end - setup_start);
    metrics.setup_genuine_ms = Milliseconds(genuine_end - setup_start);
    metrics.setup_dummy_ms = Milliseconds(setup_end - genuine_end);
    metrics.tgen_ms = tgen_ms;
    metrics.search_decrypt_ms = search_ms;
    metrics.serialized_bytes = index.logical_fingerprint_bytes() +
        options.keywords * (16 + vlse::protocol::SerializedRecordBytes<DMax>());
    metrics.communication_bytes = metrics.serialized_bytes +
        options.queries * NtlOprf::CommunicationBytesPerEvaluation();
    metrics.dummy_records = dummies;
    metrics.setup_attempts = 1;
    metrics.successful_inserts = options.keywords;
    metrics.query_successes = query_successes;
    metrics.candidate_records_total = query_successes;
    metrics.candidate_records_max = query_successes == 0 ? 0 : 1;
    metrics.decrypt_component_attempts = decrypt_component_attempts;
    return metrics;
}

template <std::size_t DMax>
Metrics Run(const Options& options) {
    return options.layout == "paired" ? RunPaired<DMax>(options)
                                      : RunOriginal<DMax>(options);
}

Metrics Dispatch(const Options& options) {
    switch (options.dmax) {
        case 1: return Run<1>(options);
        case 5: return Run<5>(options);
        case 10: return Run<10>(options);
        case 15: return Run<15>(options);
        case 20: return Run<20>(options);
        default:
            throw std::invalid_argument("--dmax must be one of 1,5,10,15,20");
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = ParseOptions(argc, argv);
        std::srand(static_cast<unsigned int>(options.seed));
        const Metrics metrics = Dispatch(options);
        std::cout << std::fixed << std::setprecision(6)
                  << "RESULT"
                  << " protocol=" << (options.layout == "paired" ? "paired_vlse" : "original_vlse")
                  << " backend=ntl_gmp_modp3072"
                  << " group=" << vlse::oprf::PublicParameters::Identifier()
                  << " modulus_bits=3072"
                  << " subgroup_bits=256"
                  << " seed=" << options.seed
                  << " keywords=" << options.keywords
                  << " queries=" << options.queries
                  << " dmax=" << options.dmax
                  << " setup_ms=" << metrics.setup_ms
                  << " setup_initialization_ms=0"
                  << " setup_genuine_ms=" << metrics.setup_genuine_ms
                  << " setup_insert_ms=" << metrics.setup_insert_ms
                  << " setup_dummy_ms=" << metrics.setup_dummy_ms
                  << " blind_precompute_ms=" << metrics.blind_precomputation_ms
                  << " tgen_ms=" << metrics.tgen_ms
                  << " search_decrypt_ms=" << metrics.search_decrypt_ms
                  << " online_ms=" << metrics.tgen_ms + metrics.search_decrypt_ms
                  << " serialized_bytes=" << metrics.serialized_bytes
                  << " cache_object_bytes=" << metrics.serialized_bytes
                  << " communication_bytes=" << metrics.communication_bytes
                  << " cold_total_bytes=" << metrics.communication_bytes
                  << " cold_amortized_bytes_per_keyword="
                  << static_cast<double>(metrics.communication_bytes) / options.queries
                  << " first_cold_query_bytes="
                  << metrics.serialized_bytes + NtlOprf::CommunicationBytesPerEvaluation()
                  << " warm_marginal_bytes_per_keyword="
                  << NtlOprf::CommunicationBytesPerEvaluation()
                  << " oprf_evaluations_per_query=1"
                  << " oprf_wire_bytes_per_query="
                  << NtlOprf::CommunicationBytesPerEvaluation()
                  << " genuine_records=" << options.keywords
                  << " dummy_records=" << metrics.dummy_records
                  << " dummy_components=" << metrics.dummy_records * options.dmax
                  << " capacity_slots=" << metrics.capacity_slots
                  << " setup_attempts=" << metrics.setup_attempts
                  << " failed_setup_attempts=" << metrics.failed_setup_attempts
                  << " successful_inserts=" << metrics.successful_inserts
                  << " failed_inserts=" << metrics.failed_inserts
                  << " eviction_steps=" << metrics.eviction_steps
                  << " rollback_count=" << metrics.rollback_count
                  << " maximum_eviction_chain=" << metrics.maximum_eviction_chain
                  << " relocation_steps=0"
                  << " maximum_relocation_chain=0"
                  << " query_successes=" << metrics.query_successes
                  << " candidate_records_total=" << metrics.candidate_records_total
                  << " candidate_records_max=" << metrics.candidate_records_max
                  << " decrypt_component_attempts="
                  << metrics.decrypt_component_attempts
                  << " keygen_included=0"
                  << " blind_precompute_included_in_online=0"
                  << " dataset_generation_included=0"
                  << " file_io_included=0"
                  << " log_io_included=0"
                  << " network_delay_included=0";
        for (std::size_t checkpoint = 0;
             checkpoint < kQueryCheckpoints.size(); ++checkpoint) {
            std::cout << " online_ms_q" << kQueryCheckpoints[checkpoint]
                      << '=' << metrics.online_checkpoint_ms[checkpoint];
        }
        std::cout << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "vlse_protocol_benchmark: " << error.what() << '\n';
        return 1;
    }
}
