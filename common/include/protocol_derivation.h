#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <cryptopp/sha.h>

#include "ntl_oprf.h"

namespace vlse::protocol {

using Token128 = unsigned __int128;
using Key128 = std::array<std::uint8_t, 16>;

struct TokenKeyPair {
    Token128 token = 0;
    Key128 key{};
};

inline std::array<std::uint8_t, CryptoPP::SHA256::DIGESTSIZE> DomainHash(
    std::string_view domain,
    const std::uint8_t* input,
    std::size_t input_size) {
    CryptoPP::SHA256 hash;
    hash.Update(
        reinterpret_cast<const CryptoPP::byte*>(domain.data()), domain.size());
    const std::uint8_t separator = 0;
    hash.Update(&separator, 1);
    hash.Update(input, input_size);
    std::array<std::uint8_t, CryptoPP::SHA256::DIGESTSIZE> digest{};
    hash.Final(digest.data());
    return digest;
}

inline TokenKeyPair DeriveTokenAndKey(const oprf::OprfOutput& output) {
    const auto token_digest = DomainHash(
        "VLSE-H1-token-v1", output.data(), output.size());
    const auto key_digest = DomainHash(
        "VLSE-H2-key-v1", output.data(), output.size());
    TokenKeyPair result;
    for (std::size_t i = 0; i < 16; ++i) {
        result.token = (result.token << 8) | token_digest[i];
        result.key[i] = key_digest[i];
    }
    return result;
}

inline Key128 LseAesKey(const oprf::OprfOutput& output) {
    // Use the least-significant 128 bits of the big-endian group encoding.
    Key128 key{};
    std::copy(output.end() - key.size(), output.end(), key.begin());
    return key;
}

}  // namespace vlse::protocol
