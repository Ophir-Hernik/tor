#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace tor::crypto {

    // Sign exactly 32 bytes (SHA-256 hash) with our PRIVATE RSA key.
    std::vector<uint8_t> rsa_sign_hash32(const std::array<uint8_t, 32>& hash32);

    // Verify signature against a peer's PUBLIC RSA key.
    // peerPublicKeyText format: "e:n" (decimal) as used by RSAEncryption::export_public_key_en()
    bool rsa_verify_hash32(const std::array<uint8_t, 32>& hash32,
        const std::vector<uint8_t>& signature,
        const std::string& peerPublicKeyText);

    // Helper: return our public key in "e:n" text format (decimal)
    std::string rsa_get_public_key_text();

    // Helper: force-load/generate persisted keypair (safe to call multiple times)
    void rsa_ensure_keypair_loaded();

} // namespace tor::crypto
