#include "crypto/sha256.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>

#pragma comment(lib, "Bcrypt.lib")

namespace tor::crypto {

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider(SHA256) failed");

    DWORD objLen = 0, cb = 0;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed"); }

    std::vector<uint8_t> obj(objLen);
    st = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptCreateHash failed"); }

    if (!data.empty()) {
        st = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        if (st != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); throw std::runtime_error("BCryptHashData failed"); }
    }

    std::array<uint8_t, 32> out{};
    st = BCryptFinishHash(hHash, out.data(), (ULONG)out.size(), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st != 0) throw std::runtime_error("BCryptFinishHash failed");
    return out;
}

} // namespace tor::crypto
