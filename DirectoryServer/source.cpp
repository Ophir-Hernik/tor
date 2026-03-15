#include <cstdlib>
#include <iostream>
#include "directory_server.h"

int main(int argc, char* argv[])
{
    // Keep directory server on a dedicated port so it does not clash with
    // the default guard relay listener (9000).
    uint16_t port = 7000;
    if (argc >= 2) {
        int parsed = std::atoi(argv[1]);
        if (parsed > 0 && parsed <= 65535) {
            port = static_cast<uint16_t>(parsed);
        }
        else {
            std::cerr << "Invalid port provided. Using default 7000.\n";
        }
    }

    DirectoryServer server(port);
    if (!server.start()) {
        return 1;
    }
    return 0;
}
