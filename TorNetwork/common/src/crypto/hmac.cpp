#include "crypto/hmac.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdexcept>

#pragma comment(lib, "Bcrypt.lib")

namespace tor::crypto {

std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& msg)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    // HMAC is enabled via the HMAC flag on the algorithm provider.
    NTSTATUS st = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (st != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider(HMAC-SHA256) failed");

    DWORD objLen = 0, cb = 0;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0);
    if (st != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed");
    }

    std::vector<uint8_t> obj(objLen);
    st = BCryptCreateHash(
        hAlg,
        &hHash,
        obj.data(),
        objLen,
        (PUCHAR)(key.empty() ? nullptr : (PUCHAR)key.data()),
        (ULONG)key.size(),
        0);
    if (st != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptCreateHash(HMAC) failed");
    }

    if (!msg.empty())
    {
        st = BCryptHashData(hHash, (PUCHAR)msg.data(), (ULONG)msg.size(), 0);
        if (st != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptHashData(HMAC) failed");
        }
    }

    std::array<uint8_t, 32> out{};
    st = BCryptFinishHash(hHash, out.data(), (ULONG)out.size(), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st != 0) throw std::runtime_error("BCryptFinishHash(HMAC) failed");
    return out;
}

} // namespace tor::crypto
