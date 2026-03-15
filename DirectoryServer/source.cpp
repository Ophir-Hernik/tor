#include <cstdlib>
#include <iostream>
#include "directory_server.h"

int main(int argc, char* argv[])
{
    uint16_t port = 9000;
    if (argc >= 2) {
        int parsed = std::atoi(argv[1]);
        if (parsed > 0 && parsed <= 65535) {
            port = static_cast<uint16_t>(parsed);
        }
        else {
            std::cerr << "Invalid port provided. Using default 9000.\n";
        }
    }

    DirectoryServer server(port);
    if (!server.start()) {
        return 1;
    }
    return 0;
}