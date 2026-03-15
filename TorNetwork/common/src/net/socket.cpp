#include "net/socket.h"
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

namespace tor::net {

void Socket::set_timeouts_ms(unsigned int recvMs, unsigned int sendMs) {
    // Winsock uses an int timeout value in milliseconds.
    int r = static_cast<int>(recvMs);
    int s = static_cast<int>(sendMs);
    ::setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&r, sizeof(r));
    ::setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO, (const char*)&s, sizeof(s));
}

void Socket::winsock_init() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
}

Socket Socket::listen_tcp(uint16_t port, int backlog) {
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) throw std::runtime_error("socket() failed");

    BOOL opt = TRUE;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (::bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        ::closesocket(s);
        throw std::runtime_error("bind() failed");
    }
    if (::listen(s, backlog) == SOCKET_ERROR) {
        ::closesocket(s);
        throw std::runtime_error("listen() failed");
    }
    return Socket(s);
}

Socket Socket::accept(Socket& listener) {
    SOCKET c = ::accept(listener.raw(), nullptr, nullptr);
    if (c == INVALID_SOCKET) throw std::runtime_error("accept() failed");
    return Socket(c);
}

Socket Socket::connect_tcp(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        throw std::runtime_error("getaddrinfo failed");
    }

    SOCKET s = INVALID_SOCKET;
    for (auto p = res; p; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (::connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        ::closesocket(s);
        s = INVALID_SOCKET;
    }
    ::freeaddrinfo(res);

    if (s == INVALID_SOCKET) throw std::runtime_error("connect() failed");
    return Socket(s);
}

void Socket::send_all(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = ::send(s_, (const char*)data + sent, (int)(len - sent), 0);
        if (n <= 0) throw std::runtime_error("send failed");
        sent += (size_t)n;
    }
}

void Socket::recv_all(uint8_t* data, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = ::recv(s_, (char*)data + got, (int)(len - got), 0);
        if (n == 0) throw std::runtime_error("recv: peer closed connection");
        if (n < 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) throw std::runtime_error("recv: timeout");
            throw std::runtime_error("recv failed");
        }
        got += (size_t)n;
    }
}

} // namespace tor::net
