#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace tor::crypto {

class AesCtr {
public:
    AesCtr(std::array<uint8_t,16> key, std::array<uint8_t,16> ivBase);

    // XORs keystream into data (encrypt/decrypt are same)
    void apply(std::vector<uint8_t>& data);

private:
    std::array<uint8_t,16> key_{};
    std::array<uint8_t,16> counter_{};
    uint64_t blockIndex_ = 0;

    void bump_counter();
};

} // namespace tor::crypto
