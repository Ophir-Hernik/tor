#include "crypto/kdf.h"
#include "crypto/sha256.h"
#include <vector>
#include <string>
#include <algorithm>

static std::array<uint8_t, 32> h(const std::array<uint8_t, 32>& shared, const char* label)
{
    std::vector<uint8_t> v(shared.begin(), shared.end());
    for (const char* p = label; *p; ++p)
    {
        v.push_back((uint8_t)*p);
    }
    return tor::crypto::sha256(v);
}

namespace tor::crypto {

    SessionKeys derive_session_keys(const std::array<uint8_t, 32>& shared32, bool isClient)
    {
        auto c2s_key = h(shared32, "c2s_key");
        auto s2c_key = h(shared32, "s2c_key");
        auto c2s_iv = h(shared32, "c2s_iv");
        auto s2c_iv = h(shared32, "s2c_iv");

        // Independent MAC keys (HMAC-SHA256) for authenticity/integrity.
        auto c2s_mac = h(shared32, "c2s_mac");
        auto s2c_mac = h(shared32, "s2c_mac");

        SessionKeys k{};

        if (isClient)
        {
            std::copy(c2s_key.begin(), c2s_key.begin() + 16, k.txKey.begin());
            std::copy(s2c_key.begin(), s2c_key.begin() + 16, k.rxKey.begin());
            std::copy(c2s_iv.begin(), c2s_iv.begin() + 16, k.txIv.begin());
            std::copy(s2c_iv.begin(), s2c_iv.begin() + 16, k.rxIv.begin());

            k.txMacKey = c2s_mac;
            k.rxMacKey = s2c_mac;
        }
        else
        {
            std::copy(s2c_key.begin(), s2c_key.begin() + 16, k.txKey.begin());
            std::copy(c2s_key.begin(), c2s_key.begin() + 16, k.rxKey.begin());
            std::copy(s2c_iv.begin(), s2c_iv.begin() + 16, k.txIv.begin());
            std::copy(c2s_iv.begin(), c2s_iv.begin() + 16, k.rxIv.begin());

            k.txMacKey = s2c_mac;
            k.rxMacKey = c2s_mac;
        }

        return k;
    }

} // namespace tor::crypto
