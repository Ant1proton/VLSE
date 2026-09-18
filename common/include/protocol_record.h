#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "aead_label.h"

namespace vlse::protocol {

template <std::size_t DMax>
struct AeadRecord {
    static_assert(DMax > 0, "DMax must be positive");
    std::array<vlse::AeadLabel, DMax> components{};
};

template <std::size_t DMax>
constexpr std::size_t SerializedRecordBytes() {
    return DMax * sizeof(vlse::AeadLabel);
}

static_assert(std::is_nothrow_copy_constructible<AeadRecord<20>>::value,
              "paired relocation needs no-throw record copies");
static_assert(std::is_nothrow_copy_assignable<AeadRecord<20>>::value,
              "paired rollback needs no-throw record assignment");

}  // namespace vlse::protocol
