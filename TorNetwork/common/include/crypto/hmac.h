#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace tor::crypto {

// HMAC-SHA256 using Windows CNG (BCrypt).
// Returns 32-byte tag.
std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& msg);

} // namespace tor::crypto
