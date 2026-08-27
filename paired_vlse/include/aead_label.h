#pragma once

// Fixed-format authenticated label records used by the paired VLSE lookup.
// The associated data is logical (epoch, query token, component index), so a
// paired record may move between physical Vacuum-Filter slots without nonce
// reuse or re-encryption.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "paired_vacuum_filter.h"

namespace vlse {

using AeadKey128 = std::array<uint8_t, 16>;

struct AeadLabel {
    static constexpr size_t kNonceBytes = 12;
    static constexpr size_t kPlaintextBytes = 16;
    static constexpr size_t kTagBytes = 16;

    std::array<uint8_t, kNonceBytes> nonce{};
    std::array<uint8_t, kPlaintextBytes> ciphertext{};
    std::array<uint8_t, kTagBytes> tag{};
};

static_assert(sizeof(AeadLabel) == 44,
              "AeadLabel must serialize as nonce || ciphertext || tag");

namespace detail {

inline void StoreLittleEndian64(uint64_t value, uint8_t* output) {
    for (size_t index = 0; index < 8; ++index) {
        output[index] = static_cast<uint8_t>(value >> (8 * index));
    }
}

inline void StoreLittleEndian32(uint32_t value, uint8_t* output) {
    for (size_t index = 0; index < 4; ++index) {
        output[index] = static_cast<uint8_t>(value >> (8 * index));
    }
}

inline uint64_t LoadLittleEndian64(const uint8_t* input) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(input[index]) << (8 * index);
    }
    return value;
}

inline std::array<uint8_t, 43> MakeAssociatedData(
    uint64_t epoch,
    Token128 token,
    uint32_t component_index) {
    // Domain separation prevents the same bytes from being reused by another
    // protocol object.  This literal is 15 bytes without the terminator.
    constexpr char kDomain[] = "VLSE-label-v1!!";
    static_assert(sizeof(kDomain) - 1 == 15, "unexpected AAD domain length");

    std::array<uint8_t, 43> aad{};
    std::memcpy(aad.data(), kDomain, sizeof(kDomain) - 1);
    StoreLittleEndian64(epoch, aad.data() + 15);
    for (size_t index = 0; index < 16; ++index) {
        aad[23 + index] = static_cast<uint8_t>(token >> (8 * index));
    }
    StoreLittleEndian32(component_index, aad.data() + 39);
    return aad;
}

class EvpCipherContext {
public:
    EvpCipherContext() : context_(EVP_CIPHER_CTX_new()) {
        if (context_ == nullptr) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }
    }
    ~EvpCipherContext() { EVP_CIPHER_CTX_free(context_); }
    EvpCipherContext(const EvpCipherContext&) = delete;
    EvpCipherContext& operator=(const EvpCipherContext&) = delete;
    EVP_CIPHER_CTX* get() { return context_; }

private:
    EVP_CIPHER_CTX* context_;
};

}  // namespace detail

inline AeadLabel EncryptLabel(
    const AeadKey128& key,
    uint64_t epoch,
    Token128 token,
    uint32_t component_index,
    bool valid,
    uint64_t document_identifier) {
    AeadLabel output;
    if (RAND_bytes(output.nonce.data(), output.nonce.size()) != 1) {
        throw std::runtime_error("RAND_bytes failed for the AES-GCM nonce");
    }

    std::array<uint8_t, AeadLabel::kPlaintextBytes> plaintext{};
    plaintext[0] = 1;  // record-format version
    plaintext[1] = valid ? 1 : 0;
    detail::StoreLittleEndian64(document_identifier, plaintext.data() + 8);
    const auto aad = detail::MakeAssociatedData(epoch, token, component_index);

    detail::EvpCipherContext context;
    int output_length = 0;
    int final_length = 0;
    if (EVP_EncryptInit_ex(context.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            output.nonce.size(), nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                           output.nonce.data()) != 1 ||
        EVP_EncryptUpdate(context.get(), nullptr, &output_length, aad.data(),
                          aad.size()) != 1 ||
        EVP_EncryptUpdate(context.get(), output.ciphertext.data(), &output_length,
                          plaintext.data(), plaintext.size()) != 1 ||
        output_length != static_cast<int>(plaintext.size()) ||
        EVP_EncryptFinal_ex(context.get(), output.ciphertext.data() + output_length,
                            &final_length) != 1 ||
        final_length != 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, output.tag.size(),
                            output.tag.data()) != 1) {
        throw std::runtime_error("AES-128-GCM encryption failed");
    }
    return output;
}

inline bool DecryptLabel(
    const AeadKey128& key,
    uint64_t epoch,
    Token128 token,
    uint32_t component_index,
    const AeadLabel& input,
    bool* valid,
    uint64_t* document_identifier) {
    if (valid == nullptr || document_identifier == nullptr) {
        throw std::invalid_argument("DecryptLabel output pointers must be non-null");
    }

    std::array<uint8_t, AeadLabel::kPlaintextBytes> plaintext{};
    const auto aad = detail::MakeAssociatedData(epoch, token, component_index);
    detail::EvpCipherContext context;
    int output_length = 0;
    int final_length = 0;
    if (EVP_DecryptInit_ex(context.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                           nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                            input.nonce.size(), nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                           input.nonce.data()) != 1 ||
        EVP_DecryptUpdate(context.get(), nullptr, &output_length, aad.data(),
                          aad.size()) != 1 ||
        EVP_DecryptUpdate(context.get(), plaintext.data(), &output_length,
                          input.ciphertext.data(), input.ciphertext.size()) != 1 ||
        output_length != static_cast<int>(plaintext.size()) ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, input.tag.size(),
                            const_cast<uint8_t*>(input.tag.data())) != 1 ||
        EVP_DecryptFinal_ex(context.get(), plaintext.data() + output_length,
                            &final_length) != 1 ||
        final_length != 0) {
        return false;
    }

    // The tag authenticates this fixed-format block.  Rejecting unknown format
    // versions and nonzero reserved bytes makes parsing deterministic.
    if (plaintext[0] != 1) {
        return false;
    }
    for (size_t index = 2; index < 8; ++index) {
        if (plaintext[index] != 0) {
            return false;
        }
    }
    *valid = plaintext[1] == 1;
    if (plaintext[1] > 1) {
        return false;
    }
    *document_identifier = detail::LoadLittleEndian64(plaintext.data() + 8);
    return true;
}

inline AeadLabel RandomDummyLabel() {
    AeadLabel dummy;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&dummy), sizeof(dummy)) != 1) {
        throw std::runtime_error("RAND_bytes failed for a dummy AEAD record");
    }
    return dummy;
}

}  // namespace vlse
