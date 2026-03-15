#include "protocol/handshake.h"
#include "protocol/packet.h"

#include "crypto/ecdh.h"
#include "crypto/kdf.h"
#include "crypto/sha256.h"
#include "crypto/rsa_auth.h"

#include <stdexcept>
#include <random>
#include <fstream>
#include <sstream>
#include <string>

#ifdef _MSC_VER
#include <cstdlib> // _dupenv_s, free
#else
#include <cstdlib> // getenv
#endif

namespace tor::protocol {

    static std::array<uint8_t, 16> rand16()
    {
        std::array<uint8_t, 16> r{};
        std::random_device rd;
        for (auto& b : r) b = (uint8_t)rd();
        return r;
    }

    static void append(std::vector<uint8_t>& v, const void* p, size_t n)
    {
        const uint8_t* b = (const uint8_t*)p;
        v.insert(v.end(), b, b + n);
    }

    static void append_u32(std::vector<uint8_t>& v, uint32_t x)
    {
        uint8_t b[4];
        b[0] = (uint8_t)(x >> 24);
        b[1] = (uint8_t)(x >> 16);
        b[2] = (uint8_t)(x >> 8);
        b[3] = (uint8_t)x;
        append(v, b, 4);
    }

    static uint32_t read_u32(const std::vector<uint8_t>& v, size_t& off)
    {
        if (off + 4 > v.size()) throw std::runtime_error("bad u32");
        uint32_t x = (uint32_t(v[off]) << 24)
            | (uint32_t(v[off + 1]) << 16)
            | (uint32_t(v[off + 2]) << 8)
            | uint32_t(v[off + 3]);
        off += 4;
        return x;
    }

    static std::vector<uint8_t> build_client_hello(const std::array<uint8_t, 16>& nonceC,
        const std::vector<uint8_t>& pubC,
        const std::vector<uint8_t>& sigC)
    {
        // [type=1][nonceC(16)][pubLen u32][pub][sigLen u32][sig]
        std::vector<uint8_t> m;
        m.push_back(1);
        append(m, nonceC.data(), nonceC.size());
        append_u32(m, (uint32_t)pubC.size());
        append(m, pubC.data(), pubC.size());
        append_u32(m, (uint32_t)sigC.size());
        append(m, sigC.data(), sigC.size());
        return m;
    }

    static std::vector<uint8_t> build_server_hello(const std::array<uint8_t, 16>& nonceS,
        const std::vector<uint8_t>& pubS,
        const std::vector<uint8_t>& sigS)
    {
        // [type=2][nonceS(16)][pubLen u32][pub][sigLen u32][sig]
        std::vector<uint8_t> m;
        m.push_back(2);
        append(m, nonceS.data(), nonceS.size());
        append_u32(m, (uint32_t)pubS.size());
        append(m, pubS.data(), pubS.size());
        append_u32(m, (uint32_t)sigS.size());
        append(m, sigS.data(), sigS.size());
        return m;
    }

    static void parse_hello_common(const std::vector<uint8_t>& msg,
        uint8_t expectedType,
        std::array<uint8_t, 16>& nonce,
        std::vector<uint8_t>& pub,
        std::vector<uint8_t>& sig)
    {
        size_t off = 0;
        if (msg.size() < 1 + 16 + 4 + 4) throw std::runtime_error("hello too short");
        if (msg[off++] != expectedType) throw std::runtime_error("wrong hello type");

        for (size_t i = 0; i < 16; i++) nonce[i] = msg[off++];

        uint32_t pubLen = read_u32(msg, off);
        if (off + pubLen > msg.size()) throw std::runtime_error("bad pub len");
        pub.assign(msg.begin() + off, msg.begin() + off + pubLen);
        off += pubLen;

        uint32_t sigLen = read_u32(msg, off);
        if (off + sigLen > msg.size()) throw std::runtime_error("bad sig len");
        sig.assign(msg.begin() + off, msg.begin() + off + sigLen);
        off += sigLen;

        if (off != msg.size()) throw std::runtime_error("trailing bytes in hello");
    }

    static std::array<uint8_t, 32> hash_client_hello(const std::array<uint8_t, 16>& nonceC,
        const std::vector<uint8_t>& pubC)
    {
        std::vector<uint8_t> t;
        const char* tag = "CHLO";
        append(t, tag, 4);
        append(t, nonceC.data(), nonceC.size());
        append(t, pubC.data(), pubC.size());
        return tor::crypto::sha256(t);
    }

    static std::array<uint8_t, 32> hash_server_hello(const std::array<uint8_t, 16>& nonceC,
        const std::array<uint8_t, 16>& nonceS,
        const std::vector<uint8_t>& pubC,
        const std::vector<uint8_t>& pubS)
    {
        std::vector<uint8_t> t;
        const char* tag = "SHLO";
        append(t, tag, 4);
        append(t, nonceC.data(), nonceC.size());
        append(t, nonceS.data(), nonceS.size());
        append(t, pubC.data(), pubC.size());
        append(t, pubS.data(), pubS.size());
        return tor::crypto::sha256(t);
    }

    static std::string safe_getenv_string(const char* name)
    {
#ifdef _MSC_VER
        char* buf = nullptr;
        size_t len = 0;
        if (_dupenv_s(&buf, &len, name) != 0 || buf == nullptr)
        {
            return "";
        }

        std::string v(buf);
        free(buf);
        return v;
#else
        const char* v = std::getenv(name);
        return v ? std::string(v) : std::string();
#endif
    }

    static std::string get_env_or_default(const char* env, const char* def)
    {
        std::string v = safe_getenv_string(env);
        return v.empty() ? std::string(def) : v;
    }

    static std::string try_load_file_text(const std::string& path)
    {
        std::ifstream f(path);
        if (!f)
        {
            return "";
        }

        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    static std::string load_first_existing_text(const std::vector<std::string>& candidates)
    {
        for (const auto& p : candidates)
        {
            const std::string t = try_load_file_text(p);
            if (!t.empty())
            {
                return t;
            }
        }

        std::string msg = "cannot open trusted key file. tried:";
        for (const auto& p : candidates)
        {
            msg += " ";
            msg += p;
        }
        throw std::runtime_error(msg);
    }

    // Server verifies the previous hop's signature with this pinned key.
    static std::string trusted_prev_public_key()
    {
        const std::string envPath = safe_getenv_string("TOR_TRUSTED_PREV_PUBKEY_FILE");
        if (!envPath.empty())
        {
            return load_first_existing_text({ envPath });
        }

        // New default names used by the node folders, with legacy fallbacks.
        return load_first_existing_text({
            "pre_key.txt",
            "trusted_prev_pubkey.txt"
        });
    }

    // Client verifies the next hop's signature with this pinned key.
    static std::string trusted_next_public_key()
    {
        const std::string envPath = safe_getenv_string("TOR_TRUSTED_NEXT_PUBKEY_FILE");
        if (!envPath.empty())
        {
            return load_first_existing_text({ envPath });
        }

        // New default names used by the node folders, with legacy fallbacks.
        return load_first_existing_text({
            "next_key.txt",
            "trusted_next_pubkey.txt"
        });
    }

    tor::crypto::SessionKeys handshake_as_server(tor::net::Socket& s)
    {
        // 1) Receive client hello
        auto msg = tor::protocol::recv_packet(s);
        std::array<uint8_t, 16> nonceC{};
        std::vector<uint8_t> pubC, sigC;
        parse_hello_common(msg, 1, nonceC, pubC, sigC);

        // 2) Verify client signature (previous hop)
        auto hC = hash_client_hello(nonceC, pubC);
        if (!tor::crypto::rsa_verify_hash32(hC, sigC, trusted_prev_public_key()))
        {
            throw std::runtime_error("CLIENT_HELLO RSA verify failed");
        }

        // 3) Generate server ECDH keypair
        auto kpS = tor::crypto::ecdh_generate_p256();
        auto nonceS = rand16();

        // 4) Sign server transcript
        auto hS = hash_server_hello(nonceC, nonceS, pubC, kpS.publicBlob);
        auto sigS = tor::crypto::rsa_sign_hash32(hS);

        // 5) Send server hello
        tor::protocol::send_packet(s, build_server_hello(nonceS, kpS.publicBlob, sigS));

        // 6) Derive shared + session keys
        auto shared = tor::crypto::ecdh_derive_shared_sha256(kpS.privateKeyHandle, pubC);
        tor::crypto::ecdh_free(kpS);
        return tor::crypto::derive_session_keys(shared, /*isClient*/false);
    }

    tor::crypto::SessionKeys handshake_as_client(tor::net::Socket& s)
    {
        // 1) Generate client ECDH keypair
        auto kpC = tor::crypto::ecdh_generate_p256();
        auto nonceC = rand16();

        // 2) Sign client hello transcript
        auto hC = hash_client_hello(nonceC, kpC.publicBlob);
        auto sigC = tor::crypto::rsa_sign_hash32(hC);

        // 3) Send client hello
        tor::protocol::send_packet(s, build_client_hello(nonceC, kpC.publicBlob, sigC));

        // 4) Receive server hello
        auto msg = tor::protocol::recv_packet(s);
        std::array<uint8_t, 16> nonceS{};
        std::vector<uint8_t> pubS, sigS;
        parse_hello_common(msg, 2, nonceS, pubS, sigS);

        // 5) Verify server signature (next hop)
        auto hS = hash_server_hello(nonceC, nonceS, kpC.publicBlob, pubS);
        if (!tor::crypto::rsa_verify_hash32(hS, sigS, trusted_next_public_key()))
        {
            throw std::runtime_error("SERVER_HELLO RSA verify failed");
        }

        // 6) Derive shared + session keys
        auto shared = tor::crypto::ecdh_derive_shared_sha256(kpC.privateKeyHandle, pubS);
        tor::crypto::ecdh_free(kpC);
        return tor::crypto::derive_session_keys(shared, /*isClient*/true);
    }

} // namespace tor::protocol
