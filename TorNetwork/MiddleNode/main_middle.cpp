#include <iostream>
#include <thread>
#include <atomic>
#include <string>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <sstream>

#include "net/socket.h"
#include "protocol/handshake.h"
#include "protocol/tor_cell.h"
#include "secure_channel.h"
#include "crypto/ecdh.h"
#include "crypto/kdf.h"
#include "crypto/onion_layer.h"

namespace
{
    constexpr std::uint16_t kDefaultListenPort  = 9001; // guard connects here
    constexpr std::uint16_t kDefaultNextHopPort = 9002; // exit listens here
    const std::string kDefaultNextHost = "127.0.0.1";

    constexpr std::uint16_t kDefaultDirectoryPort = 7000;
    const std::string kDefaultDirectoryHost = "127.0.0.1";

    bool recv_line(tor::net::Socket& sock, std::string& line) {
        line.clear();
        char ch = 0;
        while (true) {
            int n = ::recv(sock.raw(), &ch, 1, 0);
            if (n <= 0) return false;
            if (ch == '
') break;
            if (ch != '
') line.push_back(ch);
            if (line.size() > 4096) return false;
        }
        return true;
    }

    bool send_line(tor::net::Socket& sock, const std::string& line) {
        try {
            sock.send_all(reinterpret_cast<const std::uint8_t*>(line.data()), line.size());
            static const char nl = '
';
            sock.send_all(reinterpret_cast<const std::uint8_t*>(&nl), 1);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool directory_register(const std::string& dirHost, std::uint16_t dirPort,
                            const std::string& nodeName, const std::string& nodeIp,
                            std::uint16_t listenPort) {
        try {
            auto ds = tor::net::Socket::connect_tcp(dirHost, dirPort);
            std::string line;
            recv_line(ds, line);
            recv_line(ds, line);
            if (!send_line(ds, "REGISTER " + nodeName + " " + nodeIp + " " + std::to_string(listenPort))) return false;
            if (!recv_line(ds, line)) return false;
            return line.rfind("OK ", 0) == 0;
        } catch (...) {
            return false;
        }
    }

    bool directory_get(const std::string& dirHost, std::uint16_t dirPort,
                       const std::string& nodeName, std::string& host, std::uint16_t& port) {
        try {
            auto ds = tor::net::Socket::connect_tcp(dirHost, dirPort);
            std::string line;
            recv_line(ds, line);
            recv_line(ds, line);
            if (!send_line(ds, "GET " + nodeName)) return false;
            if (!recv_line(ds, line)) return false;
            std::istringstream iss(line);
            std::string tag, name;
            int p = 0;
            iss >> tag;
            if (tag != "NODE") return false;
            iss >> name >> host >> p;
            if (name != nodeName || host.empty() || p <= 0 || p > 65535) return false;
            port = static_cast<std::uint16_t>(p);
            return true;
        } catch (...) {
            return false;
        }
    }

    struct CircuitEntry {
        std::unique_ptr<tor::crypto::OnionState> onion;
    };

    class CreatedMailbox {
    public:
        void put(tor::protocol::Cell c) {
            std::lock_guard<std::mutex> lk(mu_);
            created_[c.circId] = std::move(c);
            cv_.notify_all();
        }

        tor::protocol::Cell wait_take(std::uint32_t circId, std::atomic_bool& stop) {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&]{ return stop.load() || (created_.find(circId) != created_.end()); });
            if (stop.load()) throw std::runtime_error("stopped");
            auto it = created_.find(circId);
            auto c = std::move(it->second);
            created_.erase(it);
            return c;
        }
    private:
        std::mutex mu_;
        std::condition_variable cv_;
        std::unordered_map<std::uint32_t, tor::protocol::Cell> created_;
    };

    class UpstreamSender {
    public:
        UpstreamSender(tor::SecureChannel& up, std::unordered_map<std::uint32_t, CircuitEntry>& circuits,
                       std::mutex& circuitsMu, std::atomic_bool& stop)
            : up_(up), circuits_(circuits), circuitsMu_(circuitsMu), stop_(stop) {}

        void enqueue(std::uint32_t circId, std::vector<std::uint8_t> innerBytes) {
            std::lock_guard<std::mutex> lk(mu_);
            q_.push_back(Item{circId, std::move(innerBytes)});
            cv_.notify_all();
        }

        void run() {
            try {
                while (!stop_.load()) {
                    Item item;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_.wait(lk, [&]{ return stop_.load() || !q_.empty(); });
                        if (stop_.load()) break;
                        item = std::move(q_.front());
                        q_.erase(q_.begin());
                    }

                    tor::crypto::OnionState* st = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(circuitsMu_);
                        auto it = circuits_.find(item.circId);
                        if (it != circuits_.end() && it->second.onion) st = it->second.onion.get();
                    }
                    if (!st) continue;

                    auto wrapped = tor::crypto::add_backward(*st, std::move(item.inner));
                    tor::protocol::Cell out;
                    out.circId = item.circId;
                    out.cmd = tor::protocol::CellCmd::Relay;
                    out.payload = std::move(wrapped);
                    up_.send_plain(tor::protocol::encode_cell(out));
                }
            } catch (const std::exception& e) {
                stop_.store(true);
                std::cerr << "[middle upstream_sender] stop: " << e.what() << "\n";
            }
        }

    private:
        struct Item {
            std::uint32_t circId;
            std::vector<std::uint8_t> inner;
        };

        tor::SecureChannel& up_;
        std::unordered_map<std::uint32_t, CircuitEntry>& circuits_;
        std::mutex& circuitsMu_;
        std::atomic_bool& stop_;

        std::mutex mu_;
        std::condition_variable cv_;
        std::vector<Item> q_;
    };

    void run_session(tor::net::Socket guardSock,
                     const std::string& nextHost,
                     std::uint16_t nextPort)
    {
        tor::net::Socket exitSock = tor::net::Socket::connect_tcp(nextHost, nextPort);

        auto keysFromGuard = tor::protocol::handshake_as_server(guardSock);
        auto keysToExit    = tor::protocol::handshake_as_client(exitSock);

        tor::SecureChannel chGuard(guardSock, keysFromGuard);
        tor::SecureChannel chExit(exitSock, keysToExit);

        std::atomic_bool stop{false};

        std::unordered_map<std::uint32_t, CircuitEntry> circuits;
        std::mutex circuitsMu;

        CreatedMailbox createdMb;
        UpstreamSender upstream(chGuard, circuits, circuitsMu, stop);

        // Reader from exit: dispatch CREATED replies and backward RELAY cells.
        std::thread tExitReader([&]{
            try {
                while (!stop.load()) {
                    auto msg = chExit.recv_plain();
                    auto cell = tor::protocol::decode_cell(msg);
                    if (cell.cmd == tor::protocol::CellCmd::Created) {
                        createdMb.put(std::move(cell));
                    } else if (cell.cmd == tor::protocol::CellCmd::Relay) {
                        upstream.enqueue(cell.circId, std::move(cell.payload));
                    } else if (cell.cmd == tor::protocol::CellCmd::Destroy) {
                        stop.store(true);
                        break;
                    }
                }
            } catch (const std::exception& e) {
                stop.store(true);
                guardSock.shutdown_both();
                exitSock.shutdown_both();
                std::cerr << "[middle exit_reader] stop: " << e.what() << "\n";
            }
        });

        std::thread tUpstream([&]{ upstream.run(); });

        // Forward loop: read from guard.
        try {
            while (!stop.load()) {
                auto msg = chGuard.recv_plain();
                auto cell = tor::protocol::decode_cell(msg);

                if (cell.cmd == tor::protocol::CellCmd::Create) {
                    // Circuit hop key establishment between client and middle (ECDH).
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
                    chGuard.send_plain(tor::protocol::encode_cell(reply));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Relay) {
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
                    if (tor::protocol::decode_relay(peeled, rc, rdata)) {
                        if (rc == tor::protocol::RelayCmd::Extend) {
                            // rdata is the client's ECDH pub for the next hop (exit).
                            tor::protocol::Cell createToExit;
                            createToExit.circId = cell.circId;
                            createToExit.cmd = tor::protocol::CellCmd::Create;
                            createToExit.payload = std::move(rdata);
                            chExit.send_plain(tor::protocol::encode_cell(createToExit));

                            auto created = createdMb.wait_take(cell.circId, stop);
                            if (created.cmd != tor::protocol::CellCmd::Created) {
                                throw std::runtime_error("expected CREATED from exit");
                            }

                            // Send EXTENDED back upstream (wrapped with middle backward layer via upstream sender).
                            const auto relayPlain = tor::protocol::encode_relay(tor::protocol::RelayCmd::Extended, created.payload);
                            upstream.enqueue(cell.circId, relayPlain);
                            continue;
                        }
                    }

                    // Not for middle: forward to exit.
                    tor::protocol::Cell fwd;
                    fwd.circId = cell.circId;
                    fwd.cmd = tor::protocol::CellCmd::Relay;
                    fwd.payload = std::move(peeled);
                    chExit.send_plain(tor::protocol::encode_cell(fwd));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Destroy) {
                    stop.store(true);
                    break;
                }
            }
        } catch (const std::exception& e) {
            stop.store(true);
            guardSock.shutdown_both();
            exitSock.shutdown_both();
            std::cerr << "[middle session] stop: " << e.what() << "\n";
        }

        stop.store(true);
        guardSock.shutdown_both();
        exitSock.shutdown_both();
        if (tExitReader.joinable()) tExitReader.join();
        if (tUpstream.joinable()) tUpstream.join();
    }
}

int main(int argc, char** argv)
{
    // Usage:
    //   MiddleNode.exe [listen_port] [next_host] [next_port] [directory_host] [directory_port]
    //
    // Defaults:
    //   listen_port = 9001
    //   next_host   = 127.0.0.1
    //   next_port   = 9002
    //   directory   = 127.0.0.1:7000

    try
    {
        tor::net::Socket::winsock_init();

        std::uint16_t listenPort = kDefaultListenPort;
        std::string nextHost = kDefaultNextHost;
        std::uint16_t nextPort = kDefaultNextHopPort;
        std::string dirHost = kDefaultDirectoryHost;
        std::uint16_t dirPort = kDefaultDirectoryPort;

        if (argc >= 2) listenPort = static_cast<std::uint16_t>(std::stoi(argv[1]));
        if (argc >= 3) nextHost = argv[2];
        if (argc >= 4) nextPort = static_cast<std::uint16_t>(std::stoi(argv[3]));
        if (argc >= 5) dirHost = argv[4];
        if (argc >= 6) dirPort = static_cast<std::uint16_t>(std::stoi(argv[5]));

        auto listener = tor::net::Socket::listen_tcp(listenPort);

        if (directory_register(dirHost, dirPort, "MIDDLE", "127.0.0.1", listenPort)) {
            std::cout << "[middle] registered in directory server " << dirHost << ":" << dirPort << "\n";
        } else {
            std::cout << "[middle] warning: failed to register in directory server " << dirHost << ":" << dirPort << "\n";
        }

        if (argc < 4) {
            std::string resolvedHost;
            std::uint16_t resolvedPort = 0;
            if (directory_get(dirHost, dirPort, "EXIT", resolvedHost, resolvedPort)) {
                nextHost = resolvedHost;
                nextPort = resolvedPort;
            }
        }

        std::cout << "[middle] listening on " << listenPort << ", next hop " << nextHost << ":" << nextPort << "\n";

        while (true)
        {
            auto guardSock = tor::net::Socket::accept(listener);
            std::cout << "[middle] accepted guard\n";

            run_session(std::move(guardSock), nextHost, nextPort);

            std::cout << "[middle] session ended, waiting for next guard...\n";
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "[middle] fatal: " << e.what() << "\n";
        return 1;
    }
}
