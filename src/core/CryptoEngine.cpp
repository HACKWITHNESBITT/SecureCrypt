#include "CryptoEngine.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace SecureCrypt::Core {

CryptoEngine::CryptoEngine() {
    // OpenSSL 3.0+ initialization is mostly automatic, 
    // but we can load errors for better debugging.
    ERR_load_crypto_strings();
}

CryptoEngine::~CryptoEngine() {
    EVP_cleanup();
    ERR_free_strings();
}

bool CryptoEngine::deriveKey(const std::string& password, 
                             const std::vector<unsigned char>& salt,
                             std::vector<unsigned char>& outKey,
                             std::vector<unsigned char>& outIv) {
    outKey.resize(32); // 256 bits
    outIv.resize(16);  // 128 bits for AES-CBC

    // Use 100,000 iterations as a baseline for PBKDF2
    int iterations = 100000;
    
    // We combine key and IV into a single buffer to derive them together
    std::vector<unsigned char> derived(outKey.size() + outIv.size());

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          iterations, EVP_sha256(),
                          derived.size(), derived.data()) != 1) {
        return false;
    }

    std::copy(derived.begin(), derived.begin() + 32, outKey.begin());
    std::copy(derived.begin() + 32, derived.end(), outIv.begin());

    return true;
}

bool CryptoEngine::encrypt(const std::vector<unsigned char>& plaintext,
                           const std::vector<unsigned char>& key,
                           const std::vector<unsigned char>& iv,
                           std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool success = false;
    int len;
    int ciphertext_len;

    // Initialize encryption with AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) == 1) {
        ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) == 1) {
            ciphertext_len = len;
            
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1) {
                ciphertext_len += len;
                ciphertext.resize(ciphertext_len);
                success = true;
            }
        }
    }

    if (!success) handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool CryptoEngine::decrypt(const std::vector<unsigned char>& ciphertext,
                           const std::vector<unsigned char>& key,
                           const std::vector<unsigned char>& iv,
                           std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool success = false;
    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) == 1) {
        plaintext.resize(ciphertext.size());

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) == 1) {
            plaintext_len = len;

            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1) {
                plaintext_len += len;
                plaintext.resize(plaintext_len);
                success = true;
            }
        }
    }

    if (!success) handleErrors();
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

std::vector<unsigned char> CryptoEngine::generateRandomBytes(size_t size) {
    std::vector<unsigned char> buffer(size);
    if (RAND_bytes(buffer.data(), size) != 1) {
        return {};
    }
    return buffer;
}

std::string CryptoEngine::calculateSHA256(const std::vector<unsigned char>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string CryptoEngine::calculateMD5(const std::vector<unsigned char>& data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, data.data(), data.size());
    MD5_Final(hash, &md5);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string CryptoEngine::base64Encode(const std::vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<unsigned char> CryptoEngine::base64Decode(const std::string& base64) {
    BIO *bio, *b64;
    std::vector<unsigned char> buffer(base64.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64.data(), base64.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer.data(), base64.length());
    buffer.resize(length);
    BIO_free_all(bio);

    return buffer;
}

void CryptoEngine::handleErrors() {
    unsigned long errCode;
    while ((errCode = ERR_get_error())) {
        char* err = ERR_error_string(errCode, nullptr);
        std::cerr << "OpenSSL Error: " << err << std::endl;
    }
}

} // namespace SecureCrypt::Core
