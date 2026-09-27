#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>

#include "aead_label.h"
#include "ntl_oprf.h"
#include "protocol_record.h"

namespace {
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    try {
        using Index = vlse::PairedVacuumFilter<43, vlse::protocol::AeadRecord<1>>;
        struct Case { std::size_t items, slots, bytes; };
        // Published single-label object sizes: exercise the real segmentation
        // and allocation code, including its changes of rounding granularity.
        for (const Case c : std::array<Case, 5>{{
                 {16384, 24576, 1210368}, {32768, 49152, 2420736},
                 {65536, 81920, 4034560}, {131072, 163840, 8069120},
                 {262144, 294912, 14524416}}}) {
            Index index(c.items, 0.95, 500);
            Check(index.capacity() == c.slots, "unexpected slot count");
            Check(index.total_logical_bytes() == c.bytes, "unexpected object size");
            Check(index.logical_fingerprint_bytes() == index.bucket_count() * 21,
                  "four 43-bit fingerprints must encode to 21 bytes");
            Check(index.payload_bytes() == c.slots * 44, "label byte count changed");
        }
        Check(vlse::oprf::NtlOprf::RequestBytes() == 384 &&
              vlse::oprf::NtlOprf::ResponseBytes() == 384 &&
              vlse::oprf::NtlOprf::CommunicationBytesPerEvaluation() == 768,
              "OPRF payload contract changed");

        vlse::AeadKey128 key{};
        key[0] = 9;
        constexpr std::uint64_t epoch = 3;
        constexpr vlse::Token128 token = 123;
        // Two components of one immutable record, each encrypted once.
        const auto first = vlse::EncryptLabel(key, epoch, token, 0, true, 17);
        const auto second = vlse::EncryptLabel(key, epoch, token, 1, true, 18);
        std::array<std::uint8_t, 12> first_nonce{}, second_nonce{};
        first_nonce[11] = 1;
        second_nonce[11] = 2;
        Check(first.nonce == first_nonce && second.nonce == second_nonce,
              "nonce must encode one-based component position");
        bool valid = false;
        std::uint64_t document = 0;
        Check(vlse::DecryptLabel(key, epoch, token, 0, first, &valid, &document) &&
              valid && document == 17, "first component recovery failed");
        Check(vlse::DecryptLabel(key, epoch, token, 1, second, &valid, &document) &&
              valid && document == 18, "second component recovery failed");
        Check(!vlse::DecryptLabel(key, epoch + 1, token, 0, first, &valid, &document),
              "changed epoch was accepted");
        Check(!vlse::DecryptLabel(key, epoch, token + 1, 0, first, &valid, &document),
              "changed token was accepted");
        Check(!vlse::DecryptLabel(key, epoch, token, 1, first, &valid, &document),
              "changed component index was accepted");
        for (int field = 0; field < 3; ++field) {
            auto changed = first;
            if (field == 0) changed.nonce[0] ^= 1;
            if (field == 1) changed.ciphertext[0] ^= 1;
            if (field == 2) changed.tag[0] ^= 1;
            Check(!vlse::DecryptLabel(key, epoch, token, 0, changed, &valid, &document),
                  "tampered label was accepted");
        }
        // Relocation/rebuild must reuse ciphertext rather than encrypting again.
        for (std::uint64_t seed : {7, 8}) {
            vlse::PairedVacuumFilter<43, vlse::AeadLabel> rebuilt(16, 0.95, 500, seed, seed);
            Check(rebuilt.Insert(token, first), "ciphertext reinsertion failed");
            const auto candidates = rebuilt.QueryAll(token);
            Check(candidates.size() == 1 && candidates[0].nonce == first.nonce &&
                  candidates[0].ciphertext == first.ciphertext &&
                  candidates[0].tag == first.tag, "rebuild changed ciphertext");
        }
        std::cout << "protocol_contract_test: PASS (five database sizes, nonce and authentication)\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
