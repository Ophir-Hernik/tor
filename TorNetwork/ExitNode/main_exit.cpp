#include <iostream>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <mutex>

#include "net/socket.h"
#include "protocol/handshake.h"
#include "protocol/tor_cell.h"
#include "secure_channel.h"
#include "crypto/ecdh.h"
#include "crypto/kdf.h"
#include "crypto/onion_layer.h"

namespace
{
    constexpr std::uint16_t kDefaultListenPort = 9002;

    struct CircuitEntry {
        std::unique_ptr<tor::crypto::OnionState> onion;
    };

    void run_session(tor::net::Socket middleSock)
    {
        auto keysFromMiddle = tor::protocol::handshake_as_server(middleSock);
        tor::SecureChannel chMiddle(middleSock, keysFromMiddle);

        std::unordered_map<std::uint32_t, CircuitEntry> circuits;
        std::mutex circuitsMu;

        try
        {
            while (true)
            {
                auto msg = chMiddle.recv_plain();
                auto cell = tor::protocol::decode_cell(msg);

                if (cell.cmd == tor::protocol::CellCmd::Create)
                {
                    // Circuit hop key establishment between client and exit (ECDH).
                    tor::crypto::EcdhKeyPair kp = tor::crypto::ecdh_generate_p256();
                    const auto shared = tor::crypto::ecdh_derive_shared_sha256(kp.privateKeyHandle, cell.payload);
                    auto myPub = kp.publicBlob;
                    tor::crypto::ecdh_free(kp);

                    const auto sk = tor::crypto::derive_session_keys(shared, /*isClient=*/false);

                    auto onion = std::make_unique<tor::crypto::OnionState>(
                        sk.rxKey, sk.rxIv, sk.rxMacKey,
                        sk.txKey, sk.txIv, sk.txMacKey
                    );

                    {
                        std::lock_guard<std::mutex> lk(circuitsMu);
                        circuits[cell.circId].onion = std::move(onion);
                    }

                    tor::protocol::Cell reply;
                    reply.circId = cell.circId;
                    reply.cmd = tor::protocol::CellCmd::Created;
                    reply.payload = std::move(myPub);
                    chMiddle.send_plain(tor::protocol::encode_cell(reply));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Relay)
                {
                    tor::crypto::OnionState* st = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(circuitsMu);
                        auto it = circuits.find(cell.circId);
                        if (it != circuits.end() && it->second.onion) st = it->second.onion.get();
                    }
                    if (!st) continue;

                    auto peeled = tor::crypto::peel_forward(*st, cell.payload);

                    tor::protocol::RelayCmd rc;
                    std::vector<std::uint8_t> rdata;
                    if (!tor::protocol::decode_relay(peeled, rc, rdata))
                    {
                        // No more hops beyond exit, so this is unexpected.
                        const auto errPlain = tor::protocol::encode_relay(tor::protocol::RelayCmd::Error,
                                                                         std::vector<std::uint8_t>{'b','a','d','_','r','e','l','a','y'});
                        auto wrapped = tor::crypto::add_backward(*st, errPlain);
                        tor::protocol::Cell out;
                        out.circId = cell.circId;
                        out.cmd = tor::protocol::CellCmd::Relay;
                        out.payload = std::move(wrapped);
                        chMiddle.send_plain(tor::protocol::encode_cell(out));
                        continue;
                    }

                    if (rc == tor::protocol::RelayCmd::Data)
                    {
                        // This is the real application payload. In a real Tor exit node, you'd open a TCP
                        // connection to the final destination and forward bytes. For the project, we just echo.
                        std::vector<std::uint8_t> response = rdata;

                        const auto relayPlain = tor::protocol::encode_relay(tor::protocol::RelayCmd::DataResp, response);
                        auto wrapped = tor::crypto::add_backward(*st, relayPlain);

                        tor::protocol::Cell out;
                        out.circId = cell.circId;
                        out.cmd = tor::protocol::CellCmd::Relay;
                        out.payload = std::move(wrapped);
                        chMiddle.send_plain(tor::protocol::encode_cell(out));
                        continue;
                    }

                    // Other relay commands are not expected to terminate at exit in this simplified model.
                    const auto errPlain = tor::protocol::encode_relay(tor::protocol::RelayCmd::Error,
                                                                     std::vector<std::uint8_t>{'u','n','k'});
                    auto wrapped = tor::crypto::add_backward(*st, errPlain);
                    tor::protocol::Cell out;
                    out.circId = cell.circId;
                    out.cmd = tor::protocol::CellCmd::Relay;
                    out.payload = std::move(wrapped);
                    chMiddle.send_plain(tor::protocol::encode_cell(out));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Destroy)
                {
                    break;
                }
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "[exit session] stop: " << e.what() << "\n";
        }

        middleSock.shutdown_both();
    }
}

int main(int argc, char** argv)
{
    // Usage:
    //   ExitNode.exe [listen_port]
    //
    // Default listen_port = 9002

    try
    {
        tor::net::Socket::winsock_init();

        std::uint16_t listenPort = kDefaultListenPort;
        if (argc >= 2) listenPort = static_cast<std::uint16_t>(std::stoi(argv[1]));

        auto listener = tor::net::Socket::listen_tcp(listenPort);
        std::cout << "[exit] listening on " << listenPort << "\n";

        while (true)
        {
            auto middleSock = tor::net::Socket::accept(listener);
            std::cout << "[exit] accepted middle\n";

            run_session(std::move(middleSock));

            std::cout << "[exit] session ended, waiting for next middle...\n";
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "[exit] fatal: " << e.what() << "\n";
        return 1;
    }
}
