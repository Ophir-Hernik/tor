#include "protocol/packet.h"
#include <array>
#include <cstdint>
#include <stdexcept>

namespace {

constexpr std::size_t kLengthFieldBytes = 4;

// Keep a hard cap so a malformed peer can't make us allocate huge buffers.
// 1 MiB is plenty for a demo circuit message.
constexpr std::uint32_t kMaxPacketBytes = 1024u * 1024u;

void u32_to_be(std::array<std::uint8_t, kLengthFieldBytes>& out, std::uint32_t v)
{
    out[0] = static_cast<std::uint8_t>(v >> 24);
    out[1] = static_cast<std::uint8_t>(v >> 16);
    out[2] = static_cast<std::uint8_t>(v >> 8);
    out[3] = static_cast<std::uint8_t>(v);
}

std::uint32_t be_to_u32(const std::array<std::uint8_t, kLengthFieldBytes>& in)
{
    return (std::uint32_t(in[0]) << 24) |
           (std::uint32_t(in[1]) << 16) |
           (std::uint32_t(in[2]) << 8)  |
           (std::uint32_t(in[3]));
}

} // namespace

namespace tor::protocol {

void send_packet(tor::net::Socket& s, const std::vector<std::uint8_t>& data)
{
    if (data.size() > kMaxPacketBytes)
    {
        throw std::runtime_error("packet too large");
    }

    std::array<std::uint8_t, kLengthFieldBytes> lenBe{};
    u32_to_be(lenBe, static_cast<std::uint32_t>(data.size()));

    // Frame format: [u32_be length][payload bytes...]
    s.send_all(lenBe.data(), lenBe.size());
    if (!data.empty())
    {
        s.send_all(data.data(), data.size());
    }
}

std::vector<std::uint8_t> recv_packet(tor::net::Socket& s)
{
    std::array<std::uint8_t, kLengthFieldBytes> lenBe{};
    s.recv_all(lenBe.data(), lenBe.size());

    const std::uint32_t len = be_to_u32(lenBe);
    if (len > kMaxPacketBytes)
    {
        throw std::runtime_error("bad packet length");
    }

    std::vector<std::uint8_t> buf(len);
    if (len != 0)
    {
        s.recv_all(buf.data(), buf.size());
    }
    return buf;
}

} // namespace tor::protocol
