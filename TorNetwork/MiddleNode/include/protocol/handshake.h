#pragma once
#include <array>
#include <cstdint>
#include "net/socket.h"
#include "crypto/kdf.h"

namespace tor::protocol {

// Middle acts as server on inbound (Guard->Middle) and as client on outbound (Middle->Exit)
tor::crypto::SessionKeys handshake_as_server(tor::net::Socket& s);
tor::crypto::SessionKeys handshake_as_client(tor::net::Socket& s);

} // namespace tor::protocol
