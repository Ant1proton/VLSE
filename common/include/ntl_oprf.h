#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <NTL/ZZ.h>

namespace vlse::oprf {

// The wire values are fixed-width encodings of elements in a 3072-bit finite
// field.  The prime-order subgroup and all scalars are 256 bits.  One OPRF
// invocation therefore transfers one 384-byte request and one 384-byte
// response, independently of the caller (LSE or either VLSE layout).
constexpr std::size_t kGroupElementBytes = 384;
constexpr std::size_t kScalarBytes = 32;
using OprfOutput = std::array<std::uint8_t, kGroupElementBytes>;

struct PublicParameters {
    static const NTL::ZZ& Modulus();
    static const NTL::ZZ& SubgroupOrder();
    static const NTL::ZZ& Generator();
    static const NTL::ZZ& Cofactor();
    static constexpr std::size_t EncodedElementBytes() {
        return kGroupElementBytes;
    }
    static const char* Identifier();
    static bool Validate();
};

class SecretKey {
public:
    SecretKey();
    explicit SecretKey(NTL::ZZ scalar);
    const NTL::ZZ& scalar() const { return scalar_; }

private:
    NTL::ZZ scalar_;
};

class PreparedBlind {
public:
    PreparedBlind(PreparedBlind&&) noexcept = default;
    PreparedBlind& operator=(PreparedBlind&&) noexcept = default;
    PreparedBlind(const PreparedBlind&) = delete;
    PreparedBlind& operator=(const PreparedBlind&) = delete;
    bool consumed() const { return consumed_; }
    std::size_t scalar_bits() const;
    std::size_t inverse_bits() const;

private:
    friend class NtlOprf;
    PreparedBlind(NTL::ZZ scalar, NTL::ZZ inverse)
        : scalar_(std::move(scalar)), inverse_(std::move(inverse)) {}

    NTL::ZZ scalar_;
    NTL::ZZ inverse_;
    bool consumed_ = false;
};

class NtlOprf {
public:
    explicit NtlOprf(SecretKey key);

    // Setup path: the owner already holds both the input and the PRF key.
    OprfOutput DirectEvaluate(std::string_view input) const;

    // Offline receiver work.  Its cost is reported separately and is never
    // included in the online TGen interval.
    PreparedBlind PrepareBlind() const;
    std::vector<PreparedBlind> PrepareBlindPool(std::size_t count) const;

    // Online TGen path.  This method deliberately executes the three logical
    // protocol steps even though the benchmark runs them in one process:
    // input-dependent blinding, owner evaluation, and receiver unblinding.
    OprfOutput EvaluatePrepared(
        std::string_view input,
        PreparedBlind& prepared) const;

    static constexpr std::size_t RequestBytes() {
        return kGroupElementBytes;
    }
    static constexpr std::size_t ResponseBytes() {
        return kGroupElementBytes;
    }
    static constexpr std::size_t CommunicationBytesPerEvaluation() {
        return RequestBytes() + ResponseBytes();
    }

private:
    SecretKey key_;
};

}  // namespace vlse::oprf
