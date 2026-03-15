#pragma once
#include <array>
#include <cstdint>

namespace tor::crypto {

    struct SessionKeys
    {
        std::array<uint8_t, 16> txKey{};
        std::array<uint8_t, 16> rxKey{};
        std::array<uint8_t, 16> txIv{};   // CTR base
        std::array<uint8_t, 16> rxIv{};

        // Per-direction MAC keys for packet authentication (HMAC-SHA256).
        // These are derived from the ECDH shared secret alongside the AES keys.
        std::array<uint8_t, 32> txMacKey{};
        std::array<uint8_t, 32> rxMacKey{};
    };

    // shared32 is same on both sides. isClient=true for the side that initiated that link.
    SessionKeys derive_session_keys(const std::array<uint8_t, 32>& shared32, bool isClient);

} // namespace tor::crypto
