#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/siphash.h>

#include "ntl_oprf.h"
#include "protocol_derivation.h"

namespace {

using Clock = std::chrono::steady_clock;
using Block = std::array<std::uint8_t, 16>;
using Token = vlse::oprf::OprfOutput;
using LabelList = std::vector<Block>;
using vlse::oprf::NtlOprf;
using vlse::oprf::SecretKey;

constexpr std::array<std::size_t, 5> kQueryCheckpoints{
    200, 400, 600, 800, 1000};

struct Options {
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
        if (argument == "--keywords") {
            options.keywords = ParseSize(consume("--keywords"), "--keywords");
        } else if (argument == "--queries") {
            options.queries = ParseSize(consume("--queries"), "--queries");
        } else if (argument == "--dmax") {
            options.dmax = ParseSize(consume("--dmax"), "--dmax");
        } else if (argument == "--seed") {
            options.seed = ParseSize(consume("--seed"), "--seed");
        } else if (argument == "--help") {
            std::cout << "Usage: lse_protocol_benchmark [--keywords N] "
                         "[--queries Q] [--dmax D] [--seed S]\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
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

Block EncodeDocument(std::uint64_t document) {
    Block block{};
    for (std::size_t i = 0; i < 8; ++i) {
        block[i] = static_cast<std::uint8_t>(document >> (8 * i));
    }
    return block;
}

std::uint64_t DecodeDocument(const Block& block) {
    std::uint64_t document = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        document |= static_cast<std::uint64_t>(block[i]) << (8 * i);
    }
    return document;
}

Block AuthorAesEncrypt(const Block& key, const Block& plaintext) {
    CryptoPP::AES::Encryption encryptor;
    encryptor.SetKey(key.data(), key.size());
    Block output{};
    Block zero{};
    encryptor.ProcessAndXorBlock(plaintext.data(), zero.data(), output.data());
    return output;
}

Block AuthorAesDecrypt(const Block& key, const Block& ciphertext) {
    CryptoPP::AES::Decryption decryptor;
    decryptor.SetKey(key.data(), key.size());
    Block output{};
    Block zero{};
    decryptor.ProcessAndXorBlock(ciphertext.data(), zero.data(), output.data());
    return output;
}

std::array<std::uint8_t, 16> Low128LittleEndian(const Token& token) {
    std::array<std::uint8_t, 16> low{};
    for (std::size_t i = 0; i < low.size(); ++i) {
        low[i] = token[token.size() - 1 - i];
    }
    return low;
}

class AuthorCuckooTable {
public:
    struct Statistics {
        std::uint64_t successful_inserts = 0;
        std::uint64_t failed_inserts = 0;
        std::uint64_t relocation_steps = 0;
        std::uint64_t maximum_relocation_chain = 0;
    };

    AuthorCuckooTable(std::size_t keyword_count, std::uint64_t seed)
        : bins_(std::max<std::size_t>(1, (keyword_count * 3 + 1) / 2)),
          occupied_(bins_.size(), false),
          random_(seed) {}

    bool Insert(Token token) {
        for (std::size_t relocation = 0; relocation < 1500; ++relocation) {
            for (int hash = 0; hash < 3; ++hash) {
                const std::size_t position = Position(token, hash);
                if (!occupied_[position]) {
                    occupied_[position] = true;
                    bins_[position] = std::move(token);
                    ++statistics_.successful_inserts;
                    statistics_.relocation_steps += relocation;
                    statistics_.maximum_relocation_chain =
                        std::max<std::uint64_t>(
                            statistics_.maximum_relocation_chain, relocation);
                    return true;
                }
            }
            const int hash = static_cast<int>(random_() % 3);
            const std::size_t position = Position(token, hash);
            std::swap(token, bins_[position]);
        }
        ++statistics_.failed_inserts;
        statistics_.relocation_steps += 1500;
        statistics_.maximum_relocation_chain =
            std::max<std::uint64_t>(statistics_.maximum_relocation_chain, 1500);
        return false;
    }

    const Token* Find(const Token& token) const {
        for (int hash = 0; hash < 3; ++hash) {
            const std::size_t position = Position(token, hash);
            if (occupied_[position] && bins_[position] == token) {
                return &bins_[position];
            }
        }
        return nullptr;
    }

    template <typename TokenGenerator>
    std::size_t FillEmpty(TokenGenerator&& generator) {
        std::size_t filled = 0;
        for (std::size_t i = 0; i < bins_.size(); ++i) {
            if (occupied_[i]) {
                continue;
            }
            bins_[i] = generator();
            occupied_[i] = true;
            ++filled;
        }
        return filled;
    }

    std::size_t capacity() const { return bins_.size(); }
    const Statistics& statistics() const { return statistics_; }

private:
    std::size_t Position(const Token& token, int hash_index) const {
        const auto low = Low128LittleEndian(token);
        std::array<std::uint8_t, 16> key{};
        const char literal[] = "123456123456123";
        std::copy(literal, literal + 16, key.begin());
        key[1] = static_cast<std::uint8_t>((hash_index + '0') % 128);
        CryptoPP::SipHash<2, 4, true> siphash(key.data(), key.size());
        std::array<std::uint8_t, 16> digest{};
        siphash.Update(low.data(), low.size());
        siphash.Final(digest.data());
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(digest[i]) << (8 * i);
        }
        return static_cast<std::size_t>(value % bins_.size());
    }

    std::vector<Token> bins_;
    std::vector<bool> occupied_;
    mutable std::mt19937_64 random_;
    Statistics statistics_{};
};

Token RandomToken() {
    Token token{};
    static thread_local CryptoPP::AutoSeededRandomPool random;
    random.GenerateBlock(token.data(), token.size());
    return token;
}

Block RandomBlock() {
    Block block{};
    static thread_local CryptoPP::AutoSeededRandomPool random;
    random.GenerateBlock(block.data(), block.size());
    return block;
}

struct Metrics {
    double blind_precomputation_ms = 0;
    double setup_ms = 0;
    double setup_initialization_ms = 0;
    double setup_genuine_ms = 0;
    double setup_dummy_ms = 0;
    double tgen_ms = 0;
    double search_decrypt_ms = 0;
    std::size_t serialized_bytes = 0;
    std::size_t communication_bytes = 0;
    std::size_t dummy_records = 0;
    std::size_t capacity_slots = 0;
    std::uint64_t successful_inserts = 0;
    std::uint64_t failed_inserts = 0;
    std::uint64_t relocation_steps = 0;
    std::uint64_t maximum_relocation_chain = 0;
    std::uint64_t query_successes = 0;
    std::uint64_t decrypt_component_attempts = 0;
    std::array<double, kQueryCheckpoints.size()> online_checkpoint_ms{
        -1, -1, -1, -1, -1};
};

Metrics Run(const Options& options) {
    const auto keywords = MakeKeywords(options.keywords, options.seed);
    // LSE uses independent OPRF keys for its search token and symmetric key,
    // matching the author's beta and beta1 separation.
    NtlOprf token_oprf{SecretKey{}};
    NtlOprf key_oprf{SecretKey{}};

    const auto pre_start = Clock::now();
    auto token_blinds = token_oprf.PrepareBlindPool(options.queries);
    auto key_blinds = key_oprf.PrepareBlindPool(options.queries);
    const auto pre_end = Clock::now();

    const auto setup_start = Clock::now();
    AuthorCuckooTable table(options.keywords, options.seed);
    std::map<Token, LabelList> encrypted_data;
    const auto initialization_end = Clock::now();
    for (std::size_t i = 0; i < keywords.size(); ++i) {
        const Token token = token_oprf.DirectEvaluate(keywords[i]);
        const Block key = vlse::protocol::LseAesKey(
            key_oprf.DirectEvaluate(keywords[i]));
        LabelList labels;
        labels.reserve(options.dmax);
        for (std::size_t j = 0; j < options.dmax; ++j) {
            labels.push_back(AuthorAesEncrypt(
                key, EncodeDocument(i * options.dmax + j + 1)));
        }
        encrypted_data.emplace(token, std::move(labels));
        if (!table.Insert(token)) {
            throw std::runtime_error("LSE cuckoo insertion failed at item " +
                                     std::to_string(i));
        }
    }
    const auto genuine_end = Clock::now();
    const std::size_t dummies = table.FillEmpty([&]() {
        Token token;
        do {
            token = RandomToken();
        } while (encrypted_data.find(token) != encrypted_data.end());
        LabelList labels(options.dmax);
        for (Block& label : labels) {
            label = RandomBlock();
        }
        encrypted_data.emplace(token, std::move(labels));
        return token;
    });
    const auto setup_end = Clock::now();

    double tgen_ms = 0;
    double search_ms = 0;
    std::uint64_t query_successes = 0;
    std::uint64_t decrypt_component_attempts = 0;
    std::array<double, kQueryCheckpoints.size()> online_checkpoint_ms{
        -1, -1, -1, -1, -1};
    for (std::size_t i = 0; i < options.queries; ++i) {
        const auto tgen_start = Clock::now();
        const Token token = token_oprf.EvaluatePrepared(
            keywords[i], token_blinds[i]);
        const Block key = vlse::protocol::LseAesKey(
            key_oprf.EvaluatePrepared(keywords[i], key_blinds[i]));
        const auto tgen_end = Clock::now();

        const auto search_start = Clock::now();
        const Token* stored = table.Find(token);
        if (stored == nullptr) {
            throw std::runtime_error("LSE cuckoo lookup failed");
        }
        const auto iterator = encrypted_data.find(*stored);
        if (iterator == encrypted_data.end() ||
            iterator->second.size() != options.dmax) {
            throw std::runtime_error("LSE payload lookup failed");
        }
        for (std::size_t j = 0; j < options.dmax; ++j) {
            ++decrypt_component_attempts;
            const Block plaintext = AuthorAesDecrypt(key, iterator->second[j]);
            if (DecodeDocument(plaintext) != i * options.dmax + j + 1) {
                throw std::runtime_error("LSE AES decryption mismatch");
            }
        }
        ++query_successes;
        const auto search_end = Clock::now();
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
    metrics.setup_initialization_ms = Milliseconds(initialization_end - setup_start);
    metrics.setup_genuine_ms = Milliseconds(genuine_end - initialization_end);
    metrics.setup_dummy_ms = Milliseconds(setup_end - genuine_end);
    metrics.tgen_ms = tgen_ms;
    metrics.search_decrypt_ms = search_ms;
    metrics.serialized_bytes = table.capacity() *
        (vlse::oprf::kGroupElementBytes + options.dmax * sizeof(Block));
    metrics.communication_bytes = metrics.serialized_bytes +
        options.queries * 2 * NtlOprf::CommunicationBytesPerEvaluation();
    metrics.dummy_records = dummies;
    metrics.capacity_slots = table.capacity();
    metrics.successful_inserts = table.statistics().successful_inserts;
    metrics.failed_inserts = table.statistics().failed_inserts;
    metrics.relocation_steps = table.statistics().relocation_steps;
    metrics.maximum_relocation_chain =
        table.statistics().maximum_relocation_chain;
    metrics.query_successes = query_successes;
    metrics.decrypt_component_attempts = decrypt_component_attempts;
    metrics.online_checkpoint_ms = online_checkpoint_ms;
    return metrics;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = ParseOptions(argc, argv);
        const Metrics metrics = Run(options);
        std::cout << std::fixed << std::setprecision(6)
                  << "RESULT protocol=LSE"
                  << " backend=ntl_gmp_modp3072"
                  << " group=" << vlse::oprf::PublicParameters::Identifier()
                  << " modulus_bits=3072"
                  << " subgroup_bits=256"
                  << " seed=" << options.seed
                  << " keywords=" << options.keywords
                  << " queries=" << options.queries
                  << " dmax=" << options.dmax
                  << " setup_ms=" << metrics.setup_ms
                  << " setup_initialization_ms=" << metrics.setup_initialization_ms
                  << " setup_genuine_ms=" << metrics.setup_genuine_ms
                  << " setup_insert_ms=0"
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
                  << metrics.serialized_bytes +
                         2 * NtlOprf::CommunicationBytesPerEvaluation()
                  << " warm_marginal_bytes_per_keyword="
                  << 2 * NtlOprf::CommunicationBytesPerEvaluation()
                  << " oprf_evaluations_per_query=2"
                  << " oprf_wire_bytes_per_query="
                  << 2 * NtlOprf::CommunicationBytesPerEvaluation()
                  << " genuine_records=" << options.keywords
                  << " dummy_records=" << metrics.dummy_records
                  << " dummy_components=" << metrics.dummy_records * options.dmax
                  << " capacity_slots=" << metrics.capacity_slots
                  << " setup_attempts=1"
                  << " failed_setup_attempts=0"
                  << " successful_inserts=" << metrics.successful_inserts
                  << " failed_inserts=" << metrics.failed_inserts
                  << " eviction_steps=0"
                  << " rollback_count=0"
                  << " maximum_eviction_chain=0"
                  << " relocation_steps=" << metrics.relocation_steps
                  << " maximum_relocation_chain="
                  << metrics.maximum_relocation_chain
                  << " query_successes=" << metrics.query_successes
                  << " candidate_records_total=" << metrics.query_successes
                  << " candidate_records_max="
                  << (metrics.query_successes == 0 ? 0 : 1)
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
        std::cerr << "lse_protocol_benchmark: " << error.what() << '\n';
        return 1;
    }
}
