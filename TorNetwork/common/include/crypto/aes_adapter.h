#pragma once
#include <array>
#include <cstdint>

// This project uses an AES-CTR stream construction.
// AES-CTR needs a primitive that can encrypt exactly one 16-byte block.
//
// In this repository, aes_adapter.cpp currently calls AESEncryption::encrypt_block_16,
// which is the custom AES implementation included in the project.

namespace tor::crypto {

// Encrypt one 16-byte block using AES-128 ECB (no padding), producing 16 bytes.
void aes128_encrypt_block(const std::array<uint8_t,16>& key,
                          const std::array<uint8_t,16>& in,
                          std::array<uint8_t,16>& out);

} // namespace tor::crypto
