#include "crypto/aes_adapter.h"
#include "crypto/AESEncryption.h"

#include <string>
#include <memory>

namespace tor::crypto {

    // AESEncryption takes a std::string key. The key may contain zero bytes, so we
    // must construct a length-based string and not rely on null-termination.
    static std::string key_bytes_to_string(const std::array<uint8_t, 16>& key)
    {
        return std::string(reinterpret_cast<const char*>(key.data()), key.size());
    }

    void aes128_encrypt_block(const std::array<uint8_t, 16>& key,
                              const std::array<uint8_t, 16>& in,
                              std::array<uint8_t, 16>& out)
    {
        // AES-CTR calls this per-block, so building a new AESEncryption (key expansion)
        // for every block is expensive. Cache the expanded key per-thread.
        struct Cache
        {
            bool hasKey = false;
            std::array<uint8_t, 16> lastKey{};
            std::unique_ptr<AESEncryption> aes;
        };

        thread_local Cache cache;

        if (!cache.hasKey || cache.lastKey != key)
        {
            cache.aes = std::make_unique<AESEncryption>(key_bytes_to_string(key));
            cache.lastKey = key;
            cache.hasKey = true;
        }

        cache.aes->encrypt_block_16(in, out);
    }

} // namespace tor::crypto
