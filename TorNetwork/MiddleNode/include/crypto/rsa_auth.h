#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace tor::crypto {

    // Sign exactly 32 bytes (SHA-256 hash) with our PRIVATE RSA key.
    std::vector<uint8_t> rsa_sign_hash32(const std::array<uint8_t, 32>& hash32);

    // Verify signature against a peer's PUBLIC RSA key.
    // peerPublicKeyText is in format "e:n" (decimal) in this project.
    bool rsa_verify_hash32(const std::array<uint8_t, 32>& hash32,
        const std::vector<uint8_t>& signature,
        const std::string& peerPublicKeyText);

    // ADDED: force-create the local keypair (no-op if already created).
    // Note: in the current implementation, keys are generated per-process (not persisted).
    void rsa_ensure_keypair_loaded();

    // ADDED: get our PUBLIC key in the agreed format "e:n" (decimal).
    std::string rsa_get_public_key_text();

} // namespace tor::crypto
