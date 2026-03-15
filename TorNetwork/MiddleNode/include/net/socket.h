#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>

namespace tor::net {

class Socket {
public:
    Socket() : s_(INVALID_SOCKET) {}
    explicit Socket(SOCKET s) : s_(s) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& o) noexcept : s_(o.s_) { o.s_ = INVALID_SOCKET; }
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) { close(); s_ = o.s_; o.s_ = INVALID_SOCKET; }
        return *this;
    }

    ~Socket() { close(); }

    bool valid() const { return s_ != INVALID_SOCKET; }
    SOCKET raw() const { return s_; }

    void close() noexcept {
        if (s_ != INVALID_SOCKET) { ::closesocket(s_); s_ = INVALID_SOCKET; }
    }

    // Best-effort shutdown. Useful to unblock recv/send on another thread.
    void shutdown_both() noexcept {
        if (s_ != INVALID_SOCKET) { ::shutdown(s_, SD_BOTH); }
    }

    // Set send/recv timeouts (milliseconds). 0 disables the timeout (blocking).
    void set_timeouts_ms(unsigned int recvMs, unsigned int sendMs);

    static void winsock_init();
    static Socket listen_tcp(uint16_t port, int backlog = 16);
    static Socket accept(Socket& listener);
    static Socket connect_tcp(const std::string& host, uint16_t port);

    void send_all(const uint8_t* data, size_t len);
    void recv_all(uint8_t* data, size_t len);

private:
    SOCKET s_;
};

} // namespace tor::net
