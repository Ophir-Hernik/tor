#pragma once
#include "EncryptionAlgorithm.h"
#include <vector>
#include <cstdint>
#include <string>
#include <exception>


#define ROWS 4
#define COLS 4
#define NUM_ROUNDS 10

class AESEncryption : public EncryptionAlgorithm
{
private:
    uint8_t encryptionKey[ROWS][COLS];
    uint8_t roundKeys[NUM_ROUNDS + 1][ROWS][COLS];

    static const uint8_t AES_SBOX[256];
    static const uint8_t AES_INV_SBOX[256];
    static const uint8_t FIXED_MATRIX[ROWS][COLS];
    static const uint8_t INV_FIXED_MATRIX[ROWS][COLS];
    static const uint8_t RC[NUM_ROUNDS + 1];

    void transformWord(uint8_t word[ROWS], uint8_t newWord[ROWS], const unsigned int roundNum);
    void addWords(uint8_t word1[ROWS], uint8_t word2[ROWS], uint8_t result[ROWS]);
    void arrangeWordsToKeys(uint8_t words[(NUM_ROUNDS + 1) * ROWS][COLS]);
    void expandKey();

    void shiftRowLeft(uint8_t row[COLS]);
    void shiftRowRight(uint8_t row[COLS]);
    void mixColumn(uint8_t state[ROWS][COLS], unsigned int col, const bool isInverse);

    void subBytes(uint8_t state[ROWS][COLS], const bool isInverse);
    void shiftRows(uint8_t state[ROWS][COLS], const bool isInverse);
    void addRoundKey(uint8_t state[ROWS][COLS], uint8_t roundKey[ROWS][COLS]);
    void mixColumns(uint8_t state[ROWS][COLS], const bool isInverse);

    void doRound(uint8_t state[ROWS][COLS], uint8_t roundKey[ROWS][COLS], const bool isFinal);
    void doInverseRound(uint8_t state[ROWS][COLS], uint8_t roundKey[ROWS][COLS], const bool isFinal);

    void encryptBlock(uint8_t block[ROWS][COLS]);
    void decryptBlock(uint8_t block[ROWS][COLS]);

    void addPadding(std::vector<uint8_t>& buffer);
    void removePadding(std::vector<uint8_t>& buffer);

    std::vector<uint8_t> stringToBytes(const std::string& data);
    std::string bytesToString(std::vector<uint8_t>& buffer);

    void getBlock(std::vector<uint8_t>& buffer, uint8_t block[ROWS][COLS], unsigned int start);
    void restoreBlockToBuffer(std::vector<uint8_t>& buffer, uint8_t block[ROWS][COLS], unsigned int start);

    

public:
    AESEncryption(const std::string& key);

    virtual std::string encrypt(const std::string& data) override;
    virtual std::string decrypt(const std::string& data) override;

    // ADDED: encrypt exactly one 16-byte block
    std::string encrypt_block_16(const std::string& block16);

    // ADDED: overload for adapters that use std::array<uint8_t, 16>
    std::array<uint8_t, 16> encrypt_block_16(const std::array<uint8_t, 16>& block16);

    // ADDED: matches aes_adapter’s (in, out) call
    void encrypt_block_16(const std::array<uint8_t, 16>& in,
        std::array<uint8_t, 16>& out);
};
