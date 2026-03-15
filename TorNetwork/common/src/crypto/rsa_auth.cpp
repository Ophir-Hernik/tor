#include "crypto/rsa_auth.h"
#include "crypto/RSAEncryption.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <cctype>

#ifdef _MSC_VER
#include <cstdlib> // _dupenv_s, free
#else
#include <cstdlib> // getenv
#endif

using boost::multiprecision::cpp_int;

namespace tor::crypto {

    static RSAEncryption* g_rsa = nullptr;
    static std::once_flag g_rsa_once;

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

    static std::string read_all_text(const std::string& path)
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

    static void write_all_text(const std::string& path, const std::string& text)
    {
        std::ofstream out(path, std::ios::trunc);
        if (!out)
        {
            throw std::runtime_error("failed to write file: " + path);
        }
        out << text;
        out.close();
    }

    static cpp_int hash32_to_int(const std::array<uint8_t, 32>& hash32)
    {
        cpp_int value = 0;
        for (uint8_t b : hash32)
        {
            value = (value << 8) | b;
        }
        return value;
    }

    static std::vector<uint8_t> string_to_bytes(const std::string& s)
    {
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    static std::string bytes_to_string(const std::vector<uint8_t>& v)
    {
        return std::string(v.begin(), v.end());
    }

    static bool is_truthy(const std::string& s)
    {
        if (s.empty())
        {
            return false;
        }

        std::string v;
        v.reserve(s.size());
        for (char c : s)
        {
            v.push_back((char)tolower((unsigned char)c));
        }
        return (v == "1" || v == "true" || v == "yes" || v == "y" || v == "on");
    }

    static RSAEncryption* load_or_create_rsa()
    {
        const std::string allowRegen = safe_getenv_string("TOR_RSA_ALLOW_REGEN");

        const std::string envPath = safe_getenv_string("TOR_RSA_KEYPAIR_FILE");
        const std::string primaryPath = envPath.empty() ? std::string("rsa_keypair.edn") : envPath;

        // Backward-compatible fallback name (older versions used this default).
        const std::string legacyPath = "rsa_keypair_edn.txt";

        std::vector<std::string> candidates;
        candidates.push_back(primaryPath);
        if (primaryPath != legacyPath)
        {
            candidates.push_back(legacyPath);
        }

        for (const auto& path : candidates)
        {
            const std::string edn = read_all_text(path);
            if (edn.empty())
            {
                continue;
            }

            cpp_int e, d, n;
            if (RSAEncryption::parse_private_key_edn(edn, e, d, n))
            {
                return new RSAEncryption(e, d, n);
            }

            // The file exists but can't be parsed. This should not silently create a new identity.
            if (!is_truthy(allowRegen))
            {
                throw std::runtime_error("RSA keypair file exists but is not parseable: " + path);
            }
        }

        RSAEncryption* rsa = new RSAEncryption();
        write_all_text(primaryPath, rsa->export_private_key_edn());
        return rsa;
    }

    static RSAEncryption* get_rsa()
    {
        std::call_once(g_rsa_once, []()
            {
                g_rsa = load_or_create_rsa();
            });

        return g_rsa;
    }

    void rsa_ensure_keypair_loaded()
    {
        (void)get_rsa();
    }

    std::string rsa_get_public_key_text()
    {
        return get_rsa()->export_public_key_en();
    }

    std::vector<uint8_t> rsa_sign_hash32(const std::array<uint8_t, 32>& hash32)
    {
        RSAEncryption* rsa = get_rsa();
        cpp_int h = hash32_to_int(hash32);
        cpp_int sig = rsa->sign_int(h);

        // store signature as decimal string bytes
        return string_to_bytes(sig.str());
    }

    bool rsa_verify_hash32(const std::array<uint8_t, 32>& hash32,
        const std::vector<uint8_t>& signature,
        const std::string& peerPublicKeyText)
    {
        cpp_int e, n;
        if (!RSAEncryption::parse_public_key_en(peerPublicKeyText, e, n))
        {
            return false;
        }

        RSAEncryption verifier(e, n);

        cpp_int sig;
        try
        {
            sig = cpp_int(bytes_to_string(signature));
        }
        catch (...)
        {
            return false;
        }

        cpp_int h = hash32_to_int(hash32) % verifier.get_modulus();
        cpp_int recovered = verifier.verify_int(sig);

        return recovered == h;
    }

}
