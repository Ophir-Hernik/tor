#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#include "node_info.h"

class DirectoryServer {
public:
    explicit DirectoryServer(uint16_t port);

    bool start();

private:
    void handleClient(SOCKET clientSocket);
    void cleanup();

    uint16_t port_;
    std::atomic<bool> running_{ true };
    SOCKET serverSocket_{ INVALID_SOCKET };
    std::mutex mutex_;
    std::unordered_map<std::string, NodeInfo> nodes_;
};
