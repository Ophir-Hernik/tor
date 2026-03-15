#pragma once
#include "crypto/EncryptionAlgorithm.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <string>

#define NUM_ROUNDS 12
#define MAX_CHUNK_SIZE 200

using boost::multiprecision::cpp_int;

struct EGCDResult
{
    cpp_int gcd;
    cpp_int x;
    cpp_int y;
};

class RSAEncryption : public EncryptionAlgorithm
{
public:
    RSAEncryption();
    RSAEncryption(const cpp_int& publicKey, const cpp_int& modulus);

    virtual std::string encrypt(const std::string& data) override;
    virtual std::string decrypt(const std::string& data) override;

    // Added for Tor/common usage:
    // Public key export/import in the agreed format: "e:n" (decimal).
    std::string export_public_key_en() const;

    static bool parse_public_key_en(const std::string& text,
                                    cpp_int& outE,
                                    cpp_int& outN);

    cpp_int get_public_key() const;
    cpp_int get_modulus() const;

    // Educational “raw RSA” operations for signing/verification:
    // signature = hash^d mod n
    // recovered = signature^e mod n
    cpp_int sign_int(const cpp_int& message) const;
    cpp_int verify_int(const cpp_int& signature) const;

    RSAEncryption(const cpp_int& publicKey,
        const cpp_int& privateKey,
        const cpp_int& modulus);

    cpp_int get_private_key() const;

    std::string export_private_key_edn() const;

    static bool parse_private_key_edn(const std::string& text,
        cpp_int& outE,
        cpp_int& outD,
        cpp_int& outN);


private:
    cpp_int _privateKey;
    cpp_int _publicKey;
    cpp_int _modulus;

    bool isPrime(const cpp_int& n, int rounds = 20);
    cpp_int generatePrime();
    void generateKeyPair();
    bool isPublicKey(const cpp_int& candidate, const cpp_int& totient);
    cpp_int generatePublicKey(const cpp_int& totient);
    cpp_int generatePrivateKey(const cpp_int& totient);
    std::string rsaEncryptChunks(const std::string& data, size_t maxChunkSize);
    std::string rsaDecryptChunks(const std::string& encryptedStr);

    static EGCDResult egcd(const cpp_int& a, const cpp_int& b);
    static cpp_int modinv(const cpp_int& a, const cpp_int& m);
};
