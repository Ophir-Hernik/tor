#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <stdexcept>
#include <string>
#include <algorithm>

namespace tor::protocol {

enum class CellCmd : std::uint8_t {
    Create  = 1,
    Created = 2,
    Relay   = 3,
    Destroy = 4
};

enum class RelayCmd : std::uint8_t {
    Extend     = 1,
    Extended   = 2,
    Data       = 3,
    DataResp   = 4,
    Error      = 5
};

struct Cell {
    std::uint32_t circId = 0;
    CellCmd cmd = CellCmd::Relay;
    std::vector<std::uint8_t> payload;
};

inline std::array<std::uint8_t,4> u32_be(std::uint32_t v)
{
    return { static_cast<std::uint8_t>((v >> 24) & 0xff),
             static_cast<std::uint8_t>((v >> 16) & 0xff),
             static_cast<std::uint8_t>((v >>  8) & 0xff),
             static_cast<std::uint8_t>((v >>  0) & 0xff) };
}

inline std::uint32_t be_to_u32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) <<  8) |
           (static_cast<std::uint32_t>(p[3]) <<  0);
}

// Cell bytes format (inside SecureChannel plaintext):
// [circId u32 be][cmd u8][payloadLen u32 be][payload bytes...]
inline std::vector<std::uint8_t> encode_cell(const Cell& c)
{
    const std::array<std::uint8_t,4> idBe = u32_be(c.circId);
    const std::array<std::uint8_t,4> lenBe = u32_be(static_cast<std::uint32_t>(c.payload.size()));
    std::vector<std::uint8_t> out;
    out.reserve(4 + 1 + 4 + c.payload.size());
    out.insert(out.end(), idBe.begin(), idBe.end());
    out.push_back(static_cast<std::uint8_t>(c.cmd));
    out.insert(out.end(), lenBe.begin(), lenBe.end());
    out.insert(out.end(), c.payload.begin(), c.payload.end());
    return out;
}

inline Cell decode_cell(const std::vector<std::uint8_t>& in)
{
    if (in.size() < 9) {
        throw std::runtime_error("cell too small");
    }
    Cell c;
    c.circId = be_to_u32(in.data());
    c.cmd = static_cast<CellCmd>(in[4]);
    const std::uint32_t len = be_to_u32(in.data() + 5);
    if (in.size() != 9ull + static_cast<std::size_t>(len)) {
        throw std::runtime_error("bad cell length");
    }
    c.payload.assign(in.begin() + 9, in.end());
    return c;
}

// Relay message format (after peeling one onion layer successfully):
// [magic "TOR1" 4 bytes][relayCmd u8][dataLen u32 be][data bytes...]
//
// IMPORTANT (Visual Studio compatibility):
// - Do not use C++17 inline variables here. Some project configurations/toolsets
//   accept nested namespaces but still reject inline variables.
// - Instead, expose the magic via a function returning a local static.
inline const std::array<std::uint8_t,4>& relay_magic()
{
    static const std::array<std::uint8_t,4> m = {{'T','O','R','1'}};
    return m;
}

inline std::vector<std::uint8_t> encode_relay(RelayCmd rc, const std::vector<std::uint8_t>& data)
{
    const std::array<std::uint8_t,4> lenBe = u32_be(static_cast<std::uint32_t>(data.size()));
    std::vector<std::uint8_t> out;
    out.reserve(4 + 1 + 4 + data.size());
    const std::array<std::uint8_t,4>& magic = relay_magic();
    out.insert(out.end(), magic.begin(), magic.end());
    out.push_back(static_cast<std::uint8_t>(rc));
    out.insert(out.end(), lenBe.begin(), lenBe.end());
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

inline bool decode_relay(const std::vector<std::uint8_t>& in, RelayCmd& outCmd, std::vector<std::uint8_t>& outData)
{
    if (in.size() < 9) return false;
    const std::array<std::uint8_t,4>& magic = relay_magic();
    if (!std::equal(magic.begin(), magic.end(), in.begin())) return false;
    outCmd = static_cast<RelayCmd>(in[4]);
    const std::uint32_t len = be_to_u32(in.data() + 5);
    if (in.size() != 9ull + static_cast<std::size_t>(len)) return false;
    outData.assign(in.begin() + 9, in.end());
    return true;
}

} // namespace tor::protocol
