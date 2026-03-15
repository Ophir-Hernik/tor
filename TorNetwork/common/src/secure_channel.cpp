#include "secure_channel.h"
#include "protocol/packet.h"

#include <array>
#include <stdexcept>

namespace {
    constexpr std::size_t kTagBytes = 32; // HMAC-SHA256

    bool constant_time_equal(const uint8_t* a, const uint8_t* b, std::size_t n)
    {
        uint8_t diff = 0;
        for (std::size_t i = 0; i < n; ++i)
        {
            diff |= static_cast<uint8_t>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

    std::array<uint8_t, 4> u32_be(std::uint32_t v)
    {
        return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
                static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
    }
}

namespace tor {

    SecureChannel::SecureChannel(tor::net::Socket& s, const tor::crypto::SessionKeys& keys)
        : s_(s),
        tx_(keys.txKey, keys.txIv),
        rx_(keys.rxKey, keys.rxIv),
        txMacKey_(keys.txMacKey),
        rxMacKey_(keys.rxMacKey)
    {
    }

    void SecureChannel::send_plain(std::vector<uint8_t> plain)
    {
        // Encrypt in-place
        tx_.apply(plain);

        // Authenticate: tag = HMAC(macKey, [len_be || ciphertext])
        const auto lenBe = u32_be(static_cast<std::uint32_t>(plain.size()));
        std::vector<uint8_t> macInput;
        macInput.reserve(lenBe.size() + plain.size());
        macInput.insert(macInput.end(), lenBe.begin(), lenBe.end());
        macInput.insert(macInput.end(), plain.begin(), plain.end());

        const std::vector<uint8_t> key(txMacKey_.begin(), txMacKey_.end());
        const auto tag = tor::crypto::hmac_sha256(key, macInput);

        // Send ciphertext || tag as a framed packet
        std::vector<uint8_t> out;
        out.reserve(plain.size() + kTagBytes);
        out.insert(out.end(), plain.begin(), plain.end());
        out.insert(out.end(), tag.begin(), tag.end());
        tor::protocol::send_packet(s_, out);
    }

    std::vector<uint8_t> SecureChannel::recv_plain()
    {
        auto in = tor::protocol::recv_packet(s_);
        if (in.size() < kTagBytes)
        {
            throw std::runtime_error("bad secure packet: missing auth tag");
        }

        const std::size_t cipherLen = in.size() - kTagBytes;
        const uint8_t* tagPtr = in.data() + cipherLen;

        const auto lenBe = u32_be(static_cast<std::uint32_t>(cipherLen));
        std::vector<uint8_t> macInput;
        macInput.reserve(lenBe.size() + cipherLen);
        macInput.insert(macInput.end(), lenBe.begin(), lenBe.end());
        macInput.insert(macInput.end(), in.begin(), in.begin() + cipherLen);

        const std::vector<uint8_t> key(rxMacKey_.begin(), rxMacKey_.end());
        const auto expected = tor::crypto::hmac_sha256(key, macInput);
        if (!constant_time_equal(expected.data(), tagPtr, kTagBytes))
        {
            throw std::runtime_error("bad secure packet: HMAC verification failed");
        }

        std::vector<uint8_t> cipher(in.begin(), in.begin() + cipherLen);
        rx_.apply(cipher);
        return cipher;
    }

} // namespace tor
