#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>

namespace SecureCrypt::Core {

enum class Algorithm {
    AES_256_CBC,
    AES_256_GCM,
    CHACHA20
};

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Disable copying
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;

    /**
     * @brief Derive a 256-bit key and 128-bit IV from a password and salt using PBKDF2.
     */
    static bool deriveKey(const std::string& password, 
                          const std::vector<unsigned char>& salt,
                          std::vector<unsigned char>& outKey,
                          std::vector<unsigned char>& outIv);

    /**
     * @brief Encrypt data using AES-256-CBC.
     */
    bool encrypt(const std::vector<unsigned char>& plaintext,
                 const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 std::vector<unsigned char>& ciphertext);

    /**
     * @brief Decrypt data using AES-256-CBC.
     */
    bool decrypt(const std::vector<unsigned char>& ciphertext,
                 const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& iv,
                 std::vector<unsigned char>& plaintext);

    /**
     * @brief Generate secure random bytes.
     */
    static std::vector<unsigned char> generateRandomBytes(size_t size);

    /**
     * @brief Calculate SHA-256 hash of data.
     */
    static std::string calculateSHA256(const std::vector<unsigned char>& data);

    /**
     * @brief Calculate MD5 hash of data.
     */
    static std::string calculateMD5(const std::vector<unsigned char>& data);

    /**
     * @brief Encode data to Base64.
     */
    static std::string base64Encode(const std::vector<unsigned char>& data);

    /**
     * @brief Decode data from Base64.
     */
    static std::vector<unsigned char> base64Decode(const std::string& base64);

private:
    void handleErrors();
};

} // namespace SecureCrypt::Core
