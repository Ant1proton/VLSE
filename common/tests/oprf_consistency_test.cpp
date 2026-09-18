#include <iostream>
#include <stdexcept>
#include <string>

#include "ntl_oprf.h"

int main() {
    using vlse::oprf::NtlOprf;
    using vlse::oprf::PublicParameters;
    using vlse::oprf::SecretKey;

    if (!PublicParameters::Validate()) {
        std::cerr << "fixed OPRF group validation failed\n";
        return 1;
    }

    SecretKey key{};
    if (key.scalar() <= 0 || NTL::NumBits(key.scalar()) > 256) {
        std::cerr << "OPRF key is outside the 256-bit subgroup\n";
        return 1;
    }
    NtlOprf oprf{std::move(key)};
    for (const std::string input : {"alpha", "beta", "alpha"}) {
        const auto direct = oprf.DirectEvaluate(input);
        auto prepared = oprf.PrepareBlind();
        if (prepared.scalar_bits() == 0 || prepared.scalar_bits() > 256 ||
            prepared.inverse_bits() == 0 || prepared.inverse_bits() > 256) {
            std::cerr << "prepared blind is outside the 256-bit subgroup\n";
            return 1;
        }
        const auto interactive = oprf.EvaluatePrepared(input, prepared);
        if (direct != interactive || !prepared.consumed()) {
            std::cerr << "DirectEvaluate/EvaluatePrepared mismatch\n";
            return 1;
        }
        try {
            static_cast<void>(oprf.EvaluatePrepared(input, prepared));
            std::cerr << "prepared blind reuse was not rejected\n";
            return 1;
        } catch (const std::logic_error&) {
        }
    }

    if (NtlOprf::CommunicationBytesPerEvaluation() != 768) {
        std::cerr << "unexpected OPRF wire size\n";
        return 1;
    }
    std::cout << "oprf_consistency_test: PASS\n";
    return 0;
}
