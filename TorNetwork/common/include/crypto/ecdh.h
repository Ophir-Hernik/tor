#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif
#include <array>
#include <vector>
#include <stdexcept>
#include <iostream>

namespace tor::crypto {

struct EcdhKeyPair {
    std::vector<uint8_t> publicBlob;   // BCRYPT_ECCPUBLIC_BLOB bytes
    void* privateKeyHandle = nullptr;  // BCRYPT_KEY_HANDLE stored as void*
};

EcdhKeyPair ecdh_generate_p256();
std::array<uint8_t, 32> ecdh_derive_shared_sha256(void* myPrivateKeyHandle, const std::vector<uint8_t>& peerPublicBlob);

void ecdh_free(EcdhKeyPair& kp);

} // namespace tor::crypto
