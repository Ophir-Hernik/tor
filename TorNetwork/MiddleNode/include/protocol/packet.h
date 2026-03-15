#pragma once
#include <cstdint>
#include <vector>
#include "net/socket.h"

namespace tor::protocol {

	// simple frame: [u32_be length][bytes...]
	void send_packet(tor::net::Socket& s, const std::vector<uint8_t>& data);
	std::vector<uint8_t> recv_packet(tor::net::Socket& s);

}
