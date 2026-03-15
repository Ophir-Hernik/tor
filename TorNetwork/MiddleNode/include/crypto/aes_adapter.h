#pragma once
#include <array>
#include <cstdint>

// Option 1 (default): Use Windows AES-ECB to encrypt a single 16-byte block.
// Option 2: Swap implementation to call your friend's AESEncryption block encrypt.

namespace tor::crypto {

// Encrypt one 16-byte block using AES-128 ECB (no padding), producing 16 bytes.
void aes128_encrypt_block(const std::array<uint8_t,16>& key,
                          const std::array<uint8_t,16>& in,
                          std::array<uint8_t,16>& out);

} // namespace tor::crypto
