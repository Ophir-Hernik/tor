#include "directory_server.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "socket_utils.h"

namespace {
    std::string toUpper(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return value;
    }

    std::string trim(std::string value) {
        auto notSpace = [](unsigned char c) { return !std::isspace(c); };
        value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
        value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
        return value;
    }
} // namespace

DirectoryServer::DirectoryServer(uint16_t port) : port_(port) {}

bool DirectoryServer::start() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return false;
    }

    serverSocket_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ == INVALID_SOCKET) {
        std::cerr << "Unable to create socket.\n";
        cleanup();
        return false;
    }

    int reuse = 1;
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (::bind(serverSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Bind failed.\n";
        cleanup();
        return false;
    }

    if (::listen(serverSocket_, 16) != 0) {
        std::cerr << "Listen failed.\n";
        cleanup();
        return false;
    }

    std::cout << "TOR directory server listening on port " << port_ << "...\n";
    while (running_) {
        sockaddr_in clientAddr{};
        int clientLen = sizeof(clientAddr);
        SOCKET clientSocket =
            ::accept(serverSocket_, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }
        std::thread(&DirectoryServer::handleClient, this, clientSocket).detach();
    }
    cleanup();
    return true;
}

void DirectoryServer::handleClient(SOCKET clientSocket) {
    sendAll(clientSocket,
        "WELCOME TOR DIRECTORY SERVER\n"
        "Commands: REGISTER <name> <ip> <port> | LIST | GET <name> | "
        "PING <name> | SEND <name> <message> | QUIT\n");
    std::string line;
    while (recvLine(clientSocket, line)) {
        line = trim(line);
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string command;
        iss >> command;
        command = toUpper(command);

        if (command == "QUIT") {
            sendAll(clientSocket, "BYE\n");
            break;
        }
        if (command == "REGISTER") {
            NodeInfo node;
            iss >> node.name >> node.ip >> node.port;
            if (node.name.empty() || node.ip.empty() || node.port <= 0 || node.port > 65535) {
                sendAll(clientSocket, "ERROR usage: REGISTER <name> <ip> <port>\n");
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                nodes_[node.name] = node;
            }
            sendAll(clientSocket, "OK registered " + node.name + "\n");
            continue;
        }
        if (command == "LIST") {
            std::vector<NodeInfo> snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                snapshot.reserve(nodes_.size());
                for (const auto& entry : nodes_) {
                    snapshot.push_back(entry.second);
                }
            }
            sendAll(clientSocket, "NODES " + std::to_string(snapshot.size()) + "\n");
            for (const auto& node : snapshot) {
                sendAll(clientSocket,
                    node.name + " " + node.ip + " " + std::to_string(node.port) + "\n");
            }
            sendAll(clientSocket, "END\n");
            continue;
        }
        if (command == "GET") {
            std::string name;
            iss >> name;
            if (name.empty()) {
                sendAll(clientSocket, "ERROR usage: GET <name>\n");
                continue;
            }
            NodeInfo node;
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = nodes_.find(name);
                if (it != nodes_.end()) {
                    node = it->second;
                    found = true;
                }
            }
            if (!found) {
                sendAll(clientSocket, "NOT_FOUND\n");
            }
            else {
                sendAll(clientSocket,
                    "NODE " + node.name + " " + node.ip + " " +
                    std::to_string(node.port) + "\n");
            }
            continue;
        }
        if (command == "PING") {
            std::string name;
            iss >> name;
            if (name.empty()) {
                sendAll(clientSocket, "ERROR usage: PING <name>\n");
                continue;
            }
            NodeInfo node;
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = nodes_.find(name);
                if (it != nodes_.end()) {
                    node = it->second;
                    found = true;
                }
            }
            if (!found) {
                sendAll(clientSocket, "NOT_FOUND\n");
                continue;
            }
            std::string response;
            if (!talkToNode(node, "PING", response)) {
                sendAll(clientSocket, "ERROR node unreachable\n");
                continue;
            }
            sendAll(clientSocket, "NODE_RESPONSE " + response + "\n");
            continue;
        }
        if (command == "SEND") {
            std::string name;
            iss >> name;
            std::string payload;
            std::getline(iss, payload);
            payload = trim(payload);
            if (name.empty() || payload.empty()) {
                sendAll(clientSocket, "ERROR usage: SEND <name> <message>\n");
                continue;
            }
            NodeInfo node;
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = nodes_.find(name);
                if (it != nodes_.end()) {
                    node = it->second;
                    found = true;
                }
            }
            if (!found) {
                sendAll(clientSocket, "NOT_FOUND\n");
                continue;
            }
            std::string response;
            if (!talkToNode(node, "MESSAGE " + payload, response)) {
                sendAll(clientSocket, "ERROR node unreachable\n");
                continue;
            }
            sendAll(clientSocket, "NODE_RESPONSE " + response + "\n");
            continue;
        }
        sendAll(clientSocket, "ERROR unknown command\n");
    }

    closeSocket(clientSocket);
}

void DirectoryServer::cleanup() {
    if (serverSocket_ != INVALID_SOCKET) {
        closeSocket(serverSocket_);
        serverSocket_ = INVALID_SOCKET;
    }
    WSACleanup();
}
