#include "socket_utils.h"

bool sendAll(SOCKET socketFd, const std::string& data) {
    const char* buffer = data.c_str();
    size_t remaining = data.size();
    while (remaining > 0) {
        int sent = ::send(socketFd, buffer, static_cast<int>(remaining), 0);
        if (sent <= 0) {
            return false;
        }
        buffer += sent;
        remaining -= static_cast<size_t>(sent);
    }
    return true;
}

bool recvLine(SOCKET socketFd, std::string& line) {
    line.clear();
    char ch = 0;
    while (true) {
        int received = ::recv(socketFd, &ch, 1, 0);
        if (received <= 0) {
            return false;
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            line.push_back(ch);
        }
        if (line.size() > 4096) {
            return false;
        }
    }
    return true;
}

void closeSocket(SOCKET socketFd) {
    closesocket(socketFd);
}

bool connectToNode(const NodeInfo& node, SOCKET& nodeSocket) {
    nodeSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (nodeSocket == INVALID_SOCKET) {
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(node.port));
    if (::inet_pton(AF_INET, node.ip.c_str(), &addr.sin_addr) <= 0) {
        closeSocket(nodeSocket);
        nodeSocket = INVALID_SOCKET;
        return false;
    }

    if (::connect(nodeSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closeSocket(nodeSocket);
        nodeSocket = INVALID_SOCKET;
        return false;
    }
    return true;
}

bool talkToNode(const NodeInfo& node, const std::string& payload, std::string& response) {
    SOCKET nodeSocket = INVALID_SOCKET;
    if (!connectToNode(node, nodeSocket)) {
        return false;
    }

    if (!sendAll(nodeSocket, payload + "\n")) {
        closeSocket(nodeSocket);
        return false;
    }

    bool ok = recvLine(nodeSocket, response);
    closeSocket(nodeSocket);
    return ok;
}
