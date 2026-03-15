#include "crypto/RSAEncryption.h"
#include <random>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

using boost::multiprecision::cpp_int;

static cpp_int modPow(cpp_int base, cpp_int exp, const cpp_int& mod)
{
    if (mod == 1) return 0;
    cpp_int result = 1;
    base %= mod;
    while (exp > 0)
    {
        if ((exp & 1) != 0)
            result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

std::vector<std::string> chunkData(const std::string& data, size_t chunkSize)
{
    std::vector<std::string> chunks;
    size_t pos = 0;
    while (pos < data.size())
    {
        size_t bytesToTake =
            (chunkSize < data.size() - pos) ? chunkSize : data.size() - pos;

        chunks.push_back(data.substr(pos, bytesToTake));
        pos += bytesToTake;
    }
    return chunks;
}

cpp_int bytesToInt(const std::string& chunk)
{
    cpp_int value = 0;
    for (unsigned char c : chunk)
    {
        value = (value << 8) | c;
    }
    return value;
}

std::string intToBytes(cpp_int value)
{
    std::string out;
    while (value > 0)
    {
        unsigned char byte =
            static_cast<unsigned char>((value & 0xFF).convert_to<unsigned>());
        out.insert(out.begin(), byte);
        value >>= 8;
    }
    return out;
}

std::string RSAEncryption::rsaEncryptChunks(const std::string& data, size_t maxChunkSize)
{
    std::ostringstream encryptedStream;
    auto chunks = chunkData(data, maxChunkSize);

    for (size_t i = 0; i < chunks.size(); ++i)
    {
        cpp_int m = bytesToInt(chunks[i]);
        if (m >= _modulus)
            throw std::runtime_error("Chunk value >= RSA modulus!");

        cpp_int c = modPow(m, _publicKey, _modulus);
        encryptedStream << c.str();
        if (i != chunks.size() - 1)
            encryptedStream << " ";
    }

    return encryptedStream.str();
}

std::string RSAEncryption::rsaDecryptChunks(const std::string& encryptedStr)
{
    std::istringstream encryptedStream(encryptedStr);
    std::string chunkStr;
    std::string result;

    while (encryptedStream >> chunkStr)
    {
        cpp_int c(chunkStr);
        cpp_int m = modPow(c, _privateKey, _modulus);
        result += intToBytes(m);
    }

    return result;
}

cpp_int RSAEncryption::modinv(const cpp_int& a, const cpp_int& m)
{
    EGCDResult r = egcd(a, m);
    if (r.gcd != 1)
        throw std::runtime_error("modinv: numbers are not coprime");

    cpp_int x = r.x % m;
    if (x < 0) x += m;
    return x;
}

static void secureRandomBytes(unsigned char* buffer, size_t length)
{
#ifdef _WIN32
    if (BCryptGenRandom(NULL, buffer, static_cast<ULONG>(length),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    std::random_device rd;
    for (size_t i = 0; i < length; ++i)
        buffer[i] = static_cast<unsigned char>(rd());
#endif
}

static cpp_int randomBetween(const cpp_int& low, const cpp_int& high)
{
    if (high < low)
        throw std::runtime_error("randomBetween: low > high");

    cpp_int range = high - low + 1;
    unsigned int bits = 0;
    cpp_int tmp = range - 1;
    while (tmp > 0) { tmp >>= 1; ++bits; }

    while (true)
    {
        size_t bytes = (bits + 7) / 8;
        std::vector<unsigned char> buffer(bytes);
        secureRandomBytes(buffer.data(), buffer.size());

        cpp_int candidate = 0;
        for (unsigned char b : buffer)
            candidate = (candidate << 8) | b;

        if (candidate < range)
            return low + candidate;
    }
}

RSAEncryption::RSAEncryption()
{
    generateKeyPair();
}

RSAEncryption::RSAEncryption(const cpp_int& publicKey, const cpp_int& modulus)
    : _privateKey(0), _publicKey(publicKey), _modulus(modulus)
{
}

// ADDED: full keypair constructor (for persistence)
RSAEncryption::RSAEncryption(const cpp_int& publicKey,
    const cpp_int& privateKey,
    const cpp_int& modulus)
    : _privateKey(privateKey), _publicKey(publicKey), _modulus(modulus)
{
}

std::string RSAEncryption::encrypt(const std::string& data)
{
    return rsaEncryptChunks(data, MAX_CHUNK_SIZE);
}

std::string RSAEncryption::decrypt(const std::string& data)
{
    return rsaDecryptChunks(data);
}

bool RSAEncryption::isPrime(const cpp_int& n, int rounds)
{
    if (n < 2) return false;

    static const int small_primes[] =
    {
        2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,
        53,59,61,67,71,73,79,83,89,97
    };

    for (int p : small_primes)
    {
        if (n == p) return true;
        if (n % p == 0) return false;
    }

    cpp_int d = n - 1;
    unsigned int s = 0;
    while ((d & 1) == 0)
    {
        d >>= 1;
        ++s;
    }

    for (int i = 0; i < rounds; ++i)
    {
        cpp_int a = randomBetween(2, n - 2);
        cpp_int x = modPow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (unsigned int r = 1; r < s; ++r)
        {
            x = (x * x) % n;
            if (x == n - 1)
            {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }

    return true;
}

cpp_int RSAEncryption::generatePrime()
{
    while (true)
    {
        cpp_int candidate = randomBetween(
            cpp_int(1) << 1023,
            (cpp_int(1) << 1024) - 1
        );
        candidate |= 1;
        if (isPrime(candidate, NUM_ROUNDS))
            return candidate;
    }
}

static cpp_int gcd(cpp_int a, cpp_int b)
{
    while (b != 0)
    {
        cpp_int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

void RSAEncryption::generateKeyPair()
{
    cpp_int p = generatePrime();
    cpp_int q = generatePrime();

    _modulus = p * q;
    cpp_int totient = (p - 1) * (q - 1);

    _publicKey = generatePublicKey(totient);
    _privateKey = generatePrivateKey(totient);
}

bool RSAEncryption::isPublicKey(const cpp_int& candidate, const cpp_int& totient)
{
    return candidate > 1 && candidate < totient && gcd(totient, candidate) == 1;
}

cpp_int RSAEncryption::generatePublicKey(const cpp_int& totient)
{
    cpp_int e = 65537;
    if (gcd(e, totient) != 1)
        throw std::runtime_error("Totient and exponent not coprime");

    return e;
}

cpp_int RSAEncryption::generatePrivateKey(const cpp_int& totient)
{
    return modinv(_publicKey, totient);
}

EGCDResult RSAEncryption::egcd(const cpp_int& a, const cpp_int& b)
{
    cpp_int a1 = a, b1 = b;
    cpp_int x0 = 1, y0 = 0;
    cpp_int x1 = 0, y1 = 1;

    while (b1 != 0)
    {
        cpp_int q = a1 / b1;
        cpp_int r = a1 % b1;
        cpp_int xn = x0 - q * x1;
        cpp_int yn = y0 - q * y1;

        a1 = b1;
        b1 = r;
        x0 = x1;
        y0 = y1;
        x1 = xn;
        y1 = yn;
    }

    return { a1, x0, y0 };
}

cpp_int RSAEncryption::get_public_key() const
{
    return _publicKey;
}

cpp_int RSAEncryption::get_private_key() const
{
    return _privateKey;
}

cpp_int RSAEncryption::get_modulus() const
{
    return _modulus;
}

std::string RSAEncryption::export_public_key_en() const
{
    return _publicKey.str() + ":" + _modulus.str();
}

// ADDED: export full keypair "e:d:n"
std::string RSAEncryption::export_private_key_edn() const
{
    return _publicKey.str() + ":" + _privateKey.str() + ":" + _modulus.str();
}

bool RSAEncryption::parse_public_key_en(const std::string& text,
    cpp_int& outE,
    cpp_int& outN)
{
    size_t sep = text.find(':');
    if (sep == std::string::npos) return false;

    try
    {
        outE = cpp_int(text.substr(0, sep));
        outN = cpp_int(text.substr(sep + 1));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

// ADDED: parse full keypair "e:d:n"
bool RSAEncryption::parse_private_key_edn(const std::string& text,
    cpp_int& outE,
    cpp_int& outD,
    cpp_int& outN)
{
    size_t s1 = text.find(':');
    if (s1 == std::string::npos) return false;

    size_t s2 = text.find(':', s1 + 1);
    if (s2 == std::string::npos) return false;

    try
    {
        outE = cpp_int(text.substr(0, s1));
        outD = cpp_int(text.substr(s1 + 1, s2 - s1 - 1));
        outN = cpp_int(text.substr(s2 + 1));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

cpp_int RSAEncryption::sign_int(const cpp_int& message) const
{
    cpp_int m = message % _modulus;
    return modPow(m, _privateKey, _modulus);
}

cpp_int RSAEncryption::verify_int(const cpp_int& signature) const
{
    return modPow(signature, _publicKey, _modulus);
}
