#pragma once

#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#include "node_info.h"

bool sendAll(SOCKET socketFd, const std::string& data);
bool recvLine(SOCKET socketFd, std::string& line);
void closeSocket(SOCKET socketFd);
bool connectToNode(const NodeInfo& node, SOCKET& nodeSocket);
bool talkToNode(const NodeInfo& node, const std::string& payload, std::string& response);
