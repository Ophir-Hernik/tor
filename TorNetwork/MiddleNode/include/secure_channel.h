#pragma once
#include <array>
#include <vector>
#include <atomic>
#include "net/socket.h"
#include "crypto/kdf.h"
#include "crypto/aes_ctr.h"
#include "crypto/hmac.h"

namespace tor {

class SecureChannel {
public:
    SecureChannel(tor::net::Socket& s, const tor::crypto::SessionKeys& keys);

    void send_plain(std::vector<uint8_t> plain);
    std::vector<uint8_t> recv_plain();

private:
    tor::net::Socket& s_;
    tor::crypto::AesCtr tx_;
    tor::crypto::AesCtr rx_;
    std::array<uint8_t, 32> txMacKey_{};
    std::array<uint8_t, 32> rxMacKey_{};
};

} // namespace tor
