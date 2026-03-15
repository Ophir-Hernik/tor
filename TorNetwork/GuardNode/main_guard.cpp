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

// Using anonymous namespace to limit symbol visibility to this translation unit.
namespace
{
    // Will later be replaced with Directory Server info.
    constexpr std::uint16_t kDefaultListenPort = 9000; // client connects here
    constexpr std::uint16_t kDefaultNextHopPort = 9001; // middle listens here
    const std::string kDefaultNextHopHost = "127.0.0.1";

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
            recv_line(ds, line); // welcome
            recv_line(ds, line); // help
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
            recv_line(ds, line); // welcome
            recv_line(ds, line); // help
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

    // CREATED replies from the next hop (middle) are read on a dedicated thread and
    // delivered to the forward logic via a small per-circuit mailbox.
    class CreatedMailbox {
    public:
        // Store a CREATED cell for later retrieval.
        void put(tor::protocol::Cell c) {
            std::lock_guard<std::mutex> lk(mu_);
            created_[c.circId] = std::move(c);
            cv_.notify_all();
        }

        // Wait for and take the CREATED cell for the given circuit ID.
        tor::protocol::Cell wait_take(std::uint32_t circId, std::atomic_bool& stop) {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&] {
                // Return true if we have the CREATED for this circuit, or if we're stopping.
                return stop.load() || (created_.find(circId) != created_.end());
                });
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

    // Upstream sender: the only place that advances the guard's backward onion stream.
    class UpstreamSender {
    public:
        UpstreamSender(tor::SecureChannel& up, std::unordered_map<std::uint32_t, CircuitEntry>& circuits,
            std::mutex& circuitsMu, std::atomic_bool& stop)
            : up_(up), circuits_(circuits), circuitsMu_(circuitsMu), stop_(stop) {
        }

        void enqueue(std::uint32_t circId, std::vector<std::uint8_t> innerBytes) {
            std::lock_guard<std::mutex> lk(mu_);
            q_.push_back(Item{ circId, std::move(innerBytes) });
            cv_.notify_all();
        }

        void run() {
            try {
                while (!stop_.load()) {
                    // Wait for an item to send (or stop signal).
                    Item item;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_.wait(lk, [&] { return stop_.load() || !q_.empty(); });
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
                    if (!st) continue; // circuit gone

                    auto wrapped = tor::crypto::add_backward(*st, std::move(item.inner));
                    tor::protocol::Cell out;
                    out.circId = item.circId;
                    out.cmd = tor::protocol::CellCmd::Relay;
                    out.payload = std::move(wrapped);
                    up_.send_plain(tor::protocol::encode_cell(out));
                }
            }
            catch (const std::exception& e) {
                stop_.store(true);
                std::cerr << "[guard upstream_sender] stop: " << e.what() << "\n";
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

    void run_session(tor::net::Socket clientSock,
        const std::string& nextHost,
        std::uint16_t nextPort)
    {
        // Handshake with Client FIRST. 
        // Prevents deadlock if the next hop is down.
        std::cout << "[guard] Handshaking with client...\n";
        tor::crypto::SessionKeys keysClient;
        try {
            keysClient = tor::protocol::handshake_as_server(clientSock);
        }
        catch (const std::exception& e) {
            std::cerr << "[guard] Handshake failed: " << e.what() << "\n";
            return;
        }
        tor::SecureChannel chClient(clientSock, keysClient);
        std::cout << "[guard] Client Handshake OK.\n";

        // FIX: Connect upstream AFTER client is secured.
        std::cout << "[guard] Connecting to Middle node (" << nextHost << ":" << nextPort << ")...\n";
        tor::net::Socket middleSock;
        try {
            middleSock = tor::net::Socket::connect_tcp(nextHost, nextPort);
        }
        catch (...) {
            std::cerr << "[guard] Failed to connect to middle node.\n";
            return;
        }

        auto keysMiddle = tor::protocol::handshake_as_client(middleSock);
        tor::SecureChannel chMiddle(middleSock, keysMiddle);
        std::cout << "[guard] Connected to Middle node.\n";

        std::atomic_bool stop{ false };

        std::unordered_map<std::uint32_t, CircuitEntry> circuits;
        std::mutex circuitsMu;

        CreatedMailbox createdMb;
        UpstreamSender upstream(chClient, circuits, circuitsMu, stop);

        // Reader from middle: dispatch CREATED replies and backward RELAY cells.
        std::thread tMiddleReader([&] {
            try {
                while (!stop.load()) {
                    auto msg = chMiddle.recv_plain();
                    auto cell = tor::protocol::decode_cell(msg);
                    if (cell.cmd == tor::protocol::CellCmd::Created) {
                        createdMb.put(std::move(cell));
                    }
                    else if (cell.cmd == tor::protocol::CellCmd::Relay) {
                        // Backward direction: add guard layer later via upstream sender
                        upstream.enqueue(cell.circId, std::move(cell.payload));
                    }
                    else if (cell.cmd == tor::protocol::CellCmd::Destroy) {
                        stop.store(true);
                        break;
                    }
                }
            }
            catch (const std::exception& e) {
                stop.store(true);
                // Don't close sockets here directly to avoid race with main thread usage,
                // just set stop flag.
                std::cerr << "[guard middle_reader] stop: " << e.what() << "\n";
            }
            });

        std::thread tUpstream([&] { upstream.run(); });

        // Forward loop: read from client, process CREATE and RELAY.
        try {
            while (!stop.load()) {
                auto msg = chClient.recv_plain();
                auto cell = tor::protocol::decode_cell(msg);

                if (cell.cmd == tor::protocol::CellCmd::Create) {
                    // Circuit hop key establishment between client and guard (ECDH).
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
                    chClient.send_plain(tor::protocol::encode_cell(reply));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Relay) {
                    tor::crypto::OnionState* st = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(circuitsMu);
                        auto it = circuits.find(cell.circId);
                        if (it != circuits.end() && it->second.onion) st = it->second.onion.get();
                    }
                    if (!st) {
                        continue;
                    }

                    // Peel the guard's onion layer (forward).
                    auto peeled = tor::crypto::peel_forward(*st, cell.payload);

                    tor::protocol::RelayCmd rc;
                    std::vector<std::uint8_t> rdata;
                    if (tor::protocol::decode_relay(peeled, rc, rdata)) {
                        if (rc == tor::protocol::RelayCmd::Extend) {
                            // rdata is the client's ECDH pub for the next hop (middle).
                            tor::protocol::Cell createToMiddle;
                            createToMiddle.circId = cell.circId;
                            createToMiddle.cmd = tor::protocol::CellCmd::Create;
                            createToMiddle.payload = std::move(rdata);
                            chMiddle.send_plain(tor::protocol::encode_cell(createToMiddle));

                            // Wait for CREATED from middle.
                            auto created = createdMb.wait_take(cell.circId, stop);
                            if (created.cmd != tor::protocol::CellCmd::Created) {
                                throw std::runtime_error("expected CREATED from middle");
                            }

                            // Send EXTENDED back to client (wrapped with guard backward layer via upstream sender).
                            const auto relayPlain = tor::protocol::encode_relay(tor::protocol::RelayCmd::Extended, created.payload);
                            upstream.enqueue(cell.circId, relayPlain);
                            continue;
                        }
                    }

                    // Not for guard: forward to middle as RELAY (still onion-encrypted for next hop).
                    tor::protocol::Cell fwd;
                    fwd.circId = cell.circId;
                    fwd.cmd = tor::protocol::CellCmd::Relay;
                    fwd.payload = std::move(peeled);
                    chMiddle.send_plain(tor::protocol::encode_cell(fwd));
                    continue;
                }

                if (cell.cmd == tor::protocol::CellCmd::Destroy) {
                    stop.store(true);
                    break;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[guard session] stop: " << e.what() << "\n";
        }

        stop.store(true);
        // Force close sockets to unblock any waiting threads
        clientSock.shutdown_both();
        middleSock.shutdown_both();

        if (tMiddleReader.joinable()) tMiddleReader.join();
        if (tUpstream.joinable()) tUpstream.join();
    }
}

int main(int argc, char** argv)
{
    // Usage:
    //   GuardNode.exe [listen_port] [next_host] [next_port] [directory_host] [directory_port]
    //
    // Defaults: listen=9000, next=127.0.0.1:9001, directory=127.0.0.1:7000
    try
    {
        tor::net::Socket::winsock_init();

        std::uint16_t listenPort = kDefaultListenPort;
        std::string nextHost = kDefaultNextHopHost;
        std::uint16_t nextPort = kDefaultNextHopPort;
        std::string dirHost = kDefaultDirectoryHost;
        std::uint16_t dirPort = kDefaultDirectoryPort;

        if (argc >= 2) listenPort = static_cast<std::uint16_t>(std::stoi(argv[1]));
        if (argc >= 3) nextHost = argv[2];
        if (argc >= 4) nextPort = static_cast<std::uint16_t>(std::stoi(argv[3]));
        if (argc >= 5) dirHost = argv[4];
        if (argc >= 6) dirPort = static_cast<std::uint16_t>(std::stoi(argv[5]));

        auto listener = tor::net::Socket::listen_tcp(listenPort);

        if (directory_register(dirHost, dirPort, "GUARD", "127.0.0.1", listenPort)) {
            std::cout << "[guard] registered in directory server " << dirHost << ":" << dirPort << "\n";
        } else {
            std::cout << "[guard] warning: failed to register in directory server " << dirHost << ":" << dirPort << "\n";
        }

        if (argc < 4) {
            std::string resolvedHost;
            std::uint16_t resolvedPort = 0;
            if (directory_get(dirHost, dirPort, "MIDDLE", resolvedHost, resolvedPort)) {
                nextHost = resolvedHost;
                nextPort = resolvedPort;
            }
        }

        std::cout << "[guard] listening on " << listenPort << ", next hop " << nextHost << ":" << nextPort << "\n";

        while (true)
        {
            auto clientSock = tor::net::Socket::accept(listener);
            std::cout << "[guard] accepted client\n";
            run_session(std::move(clientSock), nextHost, nextPort);
            std::cout << "[guard] session ended, waiting for next client...\n";
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "[guard] fatal: " << e.what() << "\n";
        return 1;
    }
}