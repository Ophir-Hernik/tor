#pragma once
#include <string>

class EncryptionAlgorithm
{
public:
    virtual ~EncryptionAlgorithm() = default;

    virtual std::string encrypt(const std::string& data) = 0;
    virtual std::string decrypt(const std::string& data) = 0;
};