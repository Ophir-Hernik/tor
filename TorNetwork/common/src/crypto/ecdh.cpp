#include "crypto/ecdh.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <stdexcept>
#include <vector>
#include <iostream>

#pragma comment(lib, "Bcrypt.lib")

namespace tor::crypto {

    static BCRYPT_ALG_HANDLE open_ecdh()
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
        if (st != 0)
        {
            throw std::runtime_error("BCryptOpenAlgorithmProvider(ECDH_P256) failed");
        }
        return hAlg;
    }

    EcdhKeyPair ecdh_generate_p256()
    {
        BCRYPT_ALG_HANDLE hAlg = open_ecdh();
        BCRYPT_KEY_HANDLE hKey = nullptr;

        NTSTATUS st = BCryptGenerateKeyPair(hAlg, &hKey, 256, 0);
        if (st != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptGenerateKeyPair failed");
        }

        st = BCryptFinalizeKeyPair(hKey, 0);
        if (st != 0)
        {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptFinalizeKeyPair failed");
        }

        DWORD cbPub = 0;
        st = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &cbPub, 0);
        if (st != 0)
        {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptExportKey size failed");
        }

        std::vector<uint8_t> pub(cbPub);
        st = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, pub.data(), cbPub, &cbPub, 0);
        if (st != 0)
        {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptExportKey failed");
        }

        BCryptCloseAlgorithmProvider(hAlg, 0);

        EcdhKeyPair kp;
        kp.publicBlob = std::move(pub);
        kp.privateKeyHandle = (void*)hKey;
        return kp;
    }

    std::array<uint8_t, 32> ecdh_derive_shared_sha256(void* myPrivateKeyHandle,
        const std::vector<uint8_t>& peerPublicBlob)
    {
        if (!myPrivateKeyHandle)
        {
            throw std::runtime_error("null private key");
        }

        BCRYPT_ALG_HANDLE hAlg = open_ecdh();

        BCRYPT_KEY_HANDLE hPeer = nullptr;
        NTSTATUS st = BCryptImportKeyPair(
            hAlg,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            &hPeer,
            (PUCHAR)peerPublicBlob.data(),
            (ULONG)peerPublicBlob.size(),
            0
        );

        if (st != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptImportKeyPair(peer) failed");
        }

        BCRYPT_SECRET_HANDLE hSecret = nullptr;
        st = BCryptSecretAgreement((BCRYPT_KEY_HANDLE)myPrivateKeyHandle, hPeer, &hSecret, 0);
        if (st != 0)
        {
            BCryptDestroyKey(hPeer);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            throw std::runtime_error("BCryptSecretAgreement failed");
        }

        // Derive 32 bytes using KDF_HASH(SHA256)
        // IMPORTANT FIX: cbBuffer must be BYTES and should include the null terminator.
        BCryptBuffer buf{};
        buf.BufferType = KDF_HASH_ALGORITHM;
        buf.pvBuffer = (void*)BCRYPT_SHA256_ALGORITHM;
        buf.cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(wchar_t));

        BCryptBufferDesc desc{};
        desc.ulVersion = BCRYPTBUFFER_VERSION;
        desc.cBuffers = 1;
        desc.pBuffers = &buf;

        DWORD cbOut = 0;
        std::array<uint8_t, 32> out{};
        st = BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &desc,
            out.data(), (ULONG)out.size(), &cbOut, 0);

        BCryptDestroySecret(hSecret);
        BCryptDestroyKey(hPeer);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (st != 0 || cbOut != out.size())
        {
            std::cerr << "BCryptDeriveKey failed, status=0x" << std::hex << st << std::dec << "\n";
            throw std::runtime_error("BCryptDeriveKey failed");
        }

        return out;
    }

    void ecdh_free(EcdhKeyPair& kp)
    {
        if (kp.privateKeyHandle)
        {
            BCryptDestroyKey((BCRYPT_KEY_HANDLE)kp.privateKeyHandle);
            kp.privateKeyHandle = nullptr;
        }
        kp.publicBlob.clear();
    }

} // namespace tor::crypto
