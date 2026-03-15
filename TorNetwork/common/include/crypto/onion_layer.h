#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <stdexcept>

#include "crypto/aes_ctr.h"
#include "crypto/hmac.h"

namespace tor::crypto {

struct OnionState
{
    tor::crypto::AesCtr fwdCtr;   // decrypt forward (client -> this hop)
    tor::crypto::AesCtr backCtr;  // encrypt backward (this hop -> client)
    std::array<std::uint8_t,32> fwdMac{};
    std::array<std::uint8_t,32> backMac{};

    OnionState(std::array<std::uint8_t,16> fwdKey,
               std::array<std::uint8_t,16> fwdIv,
               std::array<std::uint8_t,32> fwdMacKey,
               std::array<std::uint8_t,16> backKey,
               std::array<std::uint8_t,16> backIv,
               std::array<std::uint8_t,32> backMacKey)
        : fwdCtr(fwdKey, fwdIv),
          backCtr(backKey, backIv),
          fwdMac(fwdMacKey),
          backMac(backMacKey)
    {}
};

inline std::array<std::uint8_t,4> u32_be(std::uint32_t v)
{
    return { static_cast<std::uint8_t>((v >> 24) & 0xff),
             static_cast<std::uint8_t>((v >> 16) & 0xff),
             static_cast<std::uint8_t>((v >>  8) & 0xff),
             static_cast<std::uint8_t>((v >>  0) & 0xff) };
}

inline bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n)
{
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

// Onion layer format used here:
// - data is always "ciphertext || tag(32)". The length is known from the enclosing cell.
// - tag = HMAC(macKey, len_be(cipherLen) || ciphertext)
// - ciphertext is AES-CTR of the "inner bytes" (which could be a relay message or another onion blob).

inline std::vector<std::uint8_t> peel_forward(OnionState& st, const std::vector<std::uint8_t>& blob)
{
    const std::size_t kTagBytes = 32;
    if (blob.size() < kTagBytes) throw std::runtime_error("onion blob too small");
    const std::size_t cipherLen = blob.size() - kTagBytes;

    const std::array<std::uint8_t,4> lenBe = u32_be(static_cast<std::uint32_t>(cipherLen));
    std::vector<std::uint8_t> macInput;
    macInput.reserve(lenBe.size() + cipherLen);
    macInput.insert(macInput.end(), lenBe.begin(), lenBe.end());
    macInput.insert(macInput.end(), blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(cipherLen));

    const std::vector<std::uint8_t> key(st.fwdMac.begin(), st.fwdMac.end());
    const auto tag = tor::crypto::hmac_sha256(key, macInput);

    if (!constant_time_equal(tag.data(), blob.data() + cipherLen, kTagBytes)) {
        throw std::runtime_error("onion auth failed");
    }

    std::vector<std::uint8_t> plain(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(cipherLen));
    st.fwdCtr.apply(plain);
    return plain;
}

inline std::vector<std::uint8_t> add_backward(OnionState& st, std::vector<std::uint8_t> innerBytes)
{
    const std::size_t kTagBytes = 32;
    st.backCtr.apply(innerBytes);

    const std::array<std::uint8_t,4> lenBe = u32_be(static_cast<std::uint32_t>(innerBytes.size()));
    std::vector<std::uint8_t> macInput;
    macInput.reserve(lenBe.size() + innerBytes.size());
    macInput.insert(macInput.end(), lenBe.begin(), lenBe.end());
    macInput.insert(macInput.end(), innerBytes.begin(), innerBytes.end());

    const std::vector<std::uint8_t> key(st.backMac.begin(), st.backMac.end());
    const auto tag = tor::crypto::hmac_sha256(key, macInput);

    std::vector<std::uint8_t> out;
    out.reserve(innerBytes.size() + kTagBytes);
    out.insert(out.end(), innerBytes.begin(), innerBytes.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

} // namespace tor::crypto
