#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace tor::crypto {
std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);
} // namespace tor::crypto
