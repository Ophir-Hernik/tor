#include "crypto/aes_ctr.h"
#include "crypto/aes_adapter.h"
#include <algorithm>

namespace tor::crypto {

AesCtr::AesCtr(std::array<uint8_t,16> key, std::array<uint8_t,16> ivBase)
    : key_(key), counter_(ivBase) {}

void AesCtr::bump_counter() {
    // increment last 8 bytes as big-endian counter
    for (int i = 15; i >= 8; --i) {
        if (++counter_[i] != 0) break;
    }
}

void AesCtr::apply(std::vector<uint8_t>& data) {
    size_t off = 0;
    while (off < data.size()) {
        std::array<uint8_t,16> ks{};
        std::array<uint8_t,16> in = counter_;
        aes128_encrypt_block(key_, in, ks);

        size_t n = std::min<size_t>(16, data.size() - off);
        for (size_t i = 0; i < n; ++i) {
            data[off + i] ^= ks[i];
        }

        off += n;
        bump_counter();
    }
}

} // namespace tor::crypto
