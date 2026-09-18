#include "ntl_oprf.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

#include <cryptopp/osrng.h>
#include <cryptopp/shake.h>

namespace vlse::oprf {
namespace {

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SHAKE256;
using NTL::ZZ;

// FIPS-style finite-field parameters with L=3072 and N=256.  They were
// generated once with OpenSSL 3.6.0's DSA parameter generator; the exact PEM,
// generation command, and digest are kept in common/parameters.  The OPRF
// works in the order-q subgroup, so its key, blind, and inverse are uniformly
// sampled 256-bit scalars rather than full-size field exponents.
constexpr char kModulusHex[] =
    "CF8CB8FB77EBBFC71AA88CB93DCFB77868DC881AB89F116B"
    "4BAB48285D47F342B5A2113777D2E72112BFF2A598985FBE"
    "610F98542E0A10E5B4DE6B6FE0F1DBF69A9DBFADAC9DF2"
    "13BDF45A74784BA1B2063260B32FCAA330BB48DCB4BB14EC"
    "37C805206A39DD33E3BCAD88F17F136310104631072B11D0"
    "3F4C899E956809987017B1DB1E5958F2B30AD48477E2FC88"
    "758B87076C6BA8BD5580DBB852471AD747923FEF63420A2F"
    "F07E7D2805E813A60DA48D03D3208FC385EF86671CB14413"
    "F0138171D97120C5A7EE9987DEAC5A02723B0D4F62B38B14"
    "5A0259E140619A998C484EE214F315EEBF071B9311BDE383C"
    "0C76B669540E727B96B2A3F5F839B2F9B478979E97A5E6B"
    "13DDB3CBFE82F503D814860E8B340A8C42BDF69512826D02"
    "511CE2997EC0422F059A82EAE932B52E77DEE323124BB90A4"
    "C149D726674696966759DFDB90461A4107884153D79B47806"
    "E21972EF88A110228576114D0A504EE676A4E98C67C780B9"
    "919A37D6CD25265CCEC1C79A157AC7AE70282AFCBB36D019";

constexpr char kSubgroupOrderHex[] =
    "F5A1ED31B451B36BB7AB68BDECC471D3"
    "D4F5778F0C0A8D79D82EDABA5B2761BD";

constexpr char kGeneratorHex[] =
    "89327682373254B2B2CAECF4EA2A70FEEAD943FC23887EC1"
    "CA2607EEA5B7A139B7ED3A38042DEE4440A85370427761C4"
    "B76293B0610866B1971889F1A085B2600D48A0C030854DDF"
    "C5AEC92A2997076B8AB532531FCCF86683111DD8C1F0B7A3"
    "891D5CC1ECEA281FF25A0CD977D8FDAE5E0CB8B2869EC9A"
    "C49C6A462E038B0B28F9CABBA59255BA6EF259460D79EEB0"
    "2E70EC5773E625DA5A98AE83310DD6D4FD04874CB9F1EEFE"
    "81247C6165E0989C12F2B8AE70CA8F3E89701F87977730A"
    "552B4A77DEDC64E5CE2BCEF0F81F66188D00E67B8E464A7"
    "E868B10DDBD70FFF4F890BC5D84367D6AD8E1C15FDAC383"
    "D935DD20EC38649848480354049DE3A373813C1618741C09"
    "55CF7BB325A6158AA56DD4ACA6B40ABDE304EB283A0830AB"
    "7E3315FAB03CEFE2591216FDAECE7C9F01D11084376254A2"
    "7B6F4CAE9286E7958BF9EEE40645A7D422CE46015C53435A"
    "D2D46D5D2EA424DFC83912B39D1AC9113583A85CA7743EF"
    "CB7AAAB03A3A52A9DDDF51449229BA8CE04A5B0870DBE9068F20D";

ZZ HexToZZ(const char* hex) {
    ZZ value(0);
    for (const char* cursor = hex; *cursor != '\0'; ++cursor) {
        value <<= 4;
        if (*cursor >= '0' && *cursor <= '9') {
            value += *cursor - '0';
        } else if (*cursor >= 'A' && *cursor <= 'F') {
            value += *cursor - 'A' + 10;
        } else if (*cursor >= 'a' && *cursor <= 'f') {
            value += *cursor - 'a' + 10;
        } else {
            throw std::logic_error("invalid hexadecimal group parameter");
        }
    }
    return value;
}

ZZ FromBigEndian(const std::uint8_t* input, std::size_t length) {
    ZZ value(0);
    for (std::size_t i = 0; i < length; ++i) {
        value <<= 8;
        value += input[i];
    }
    return value;
}

OprfOutput ToBigEndian(const ZZ& input) {
    if (input < 0 || input >= PublicParameters::Modulus()) {
        throw std::invalid_argument("group element is outside the field");
    }
    OprfOutput output{};
    ZZ value = input;
    for (std::size_t offset = 0; offset < output.size(); ++offset) {
        const std::size_t index = output.size() - 1 - offset;
        output[index] = static_cast<std::uint8_t>(NTL::conv<unsigned long>(
            value & 0xff));
        value >>= 8;
    }
    if (value != 0) {
        throw std::logic_error("group element does not fit fixed encoding");
    }
    return output;
}

AutoSeededRandomPool& RandomPool() {
    static thread_local AutoSeededRandomPool pool;
    return pool;
}

ZZ RandomScalar() {
    std::array<std::uint8_t, kScalarBytes> bytes{};
    const ZZ& q = PublicParameters::SubgroupOrder();
    for (;;) {
        RandomPool().GenerateBlock(bytes.data(), bytes.size());
        ZZ scalar = FromBigEndian(bytes.data(), bytes.size());
        if (scalar > 0 && scalar < q) {
            return scalar;
        }
    }
}

void UpdateString(SHAKE256& shake, std::string_view value) {
    shake.Update(
        reinterpret_cast<const CryptoPP::byte*>(value.data()), value.size());
}

ZZ HashToGroup(std::string_view input) {
    // SHAKE emits 128 extra bits before reduction, making reduction bias
    // negligible.  Exponentiation by (p-1)/q maps the field element negligibly
    // close to uniform in the order-q subgroup; identity is rejected.
    constexpr std::size_t kWideBytes = kGroupElementBytes + 16;
    std::array<std::uint8_t, kWideBytes> wide{};
    constexpr std::string_view kDomain = "VLSE/LSE-H2G-FFC3072Q256-v1";
    for (std::uint32_t counter = 0;; ++counter) {
        SHAKE256 shake(static_cast<unsigned int>(wide.size()));
        UpdateString(shake, kDomain);
        const std::uint8_t separator = 0;
        shake.Update(&separator, 1);
        UpdateString(shake, input);
        const std::array<std::uint8_t, 4> encoded_counter{
            static_cast<std::uint8_t>(counter >> 24),
            static_cast<std::uint8_t>(counter >> 16),
            static_cast<std::uint8_t>(counter >> 8),
            static_cast<std::uint8_t>(counter)};
        shake.Update(encoded_counter.data(), encoded_counter.size());
        shake.TruncatedFinal(wide.data(), wide.size());

        const ZZ& p = PublicParameters::Modulus();
        const ZZ candidate = (FromBigEndian(wide.data(), wide.size()) % (p - 3)) + 2;
        const ZZ element = NTL::PowerMod(
            candidate, PublicParameters::Cofactor(), p);
        if (element != 1) {
            return element;
        }
    }
}

}  // namespace

const ZZ& PublicParameters::Modulus() {
    static const ZZ modulus = HexToZZ(kModulusHex);
    return modulus;
}

const ZZ& PublicParameters::SubgroupOrder() {
    static const ZZ order = HexToZZ(kSubgroupOrderHex);
    return order;
}

const ZZ& PublicParameters::Generator() {
    static const ZZ generator = HexToZZ(kGeneratorHex);
    return generator;
}

const ZZ& PublicParameters::Cofactor() {
    static const ZZ cofactor = (Modulus() - 1) / SubgroupOrder();
    return cofactor;
}

const char* PublicParameters::Identifier() {
    return "ffc3072-q256-shake256-v1";
}

bool PublicParameters::Validate() {
    const ZZ& p = Modulus();
    const ZZ& q = SubgroupOrder();
    const ZZ& g = Generator();
    return NTL::NumBits(p) == 3072 && NTL::NumBits(q) == 256 &&
           (p - 1) % q == 0 && Cofactor() * q == p - 1 &&
           NTL::ProbPrime(p, 32) != 0 && NTL::ProbPrime(q, 32) != 0 &&
           g > 1 && g < p && NTL::PowerMod(g, q, p) == 1;
}

SecretKey::SecretKey() : scalar_(RandomScalar()) {}

SecretKey::SecretKey(ZZ scalar) : scalar_(std::move(scalar)) {
    if (scalar_ <= 0 || scalar_ >= PublicParameters::SubgroupOrder()) {
        throw std::invalid_argument("OPRF secret scalar must be in [1,q-1]");
    }
}

NtlOprf::NtlOprf(SecretKey key) : key_(std::move(key)) {}

std::size_t PreparedBlind::scalar_bits() const {
    return static_cast<std::size_t>(NTL::NumBits(scalar_));
}

std::size_t PreparedBlind::inverse_bits() const {
    return static_cast<std::size_t>(NTL::NumBits(inverse_));
}

OprfOutput NtlOprf::DirectEvaluate(std::string_view input) const {
    const ZZ evaluated = NTL::PowerMod(
        HashToGroup(input), key_.scalar(), PublicParameters::Modulus());
    return ToBigEndian(evaluated);
}

PreparedBlind NtlOprf::PrepareBlind() const {
    ZZ scalar = RandomScalar();
    ZZ inverse = NTL::InvMod(scalar, PublicParameters::SubgroupOrder());
    return PreparedBlind(std::move(scalar), std::move(inverse));
}

std::vector<PreparedBlind> NtlOprf::PrepareBlindPool(std::size_t count) const {
    std::vector<PreparedBlind> pool;
    pool.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        pool.emplace_back(PrepareBlind());
    }
    return pool;
}

OprfOutput NtlOprf::EvaluatePrepared(
    std::string_view input,
    PreparedBlind& prepared) const {
    if (prepared.consumed_) {
        throw std::logic_error("prepared OPRF blind was reused");
    }
    prepared.consumed_ = true;

    const ZZ& p = PublicParameters::Modulus();
    const ZZ request = NTL::PowerMod(HashToGroup(input), prepared.scalar_, p);
    const ZZ response = NTL::PowerMod(request, key_.scalar(), p);
    const ZZ unblinded = NTL::PowerMod(response, prepared.inverse_, p);
    return ToBigEndian(unblinded);
}

}  // namespace vlse::oprf
