#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include "core/CryptoEngine.h"
#include "file/FileManager.h"

using namespace SecureCrypt::Core;
using namespace SecureCrypt::File;

void printUsage() {
    std::cout << "Usage: SecureCrypt <encrypt|decrypt> <file> <password>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];
    std::string filePath = argv[2];
    std::string password = argv[3];

    CryptoEngine engine;

    if (mode == "encrypt") {
        std::cout << "Encrypting " << filePath << "...\n";
        
        auto plaintext = FileManager::readFile(filePath);
        if (plaintext.empty()) {
            std::cerr << "Failed to read file or file is empty.\n";
            return 1;
        }

        auto salt = CryptoEngine::generateRandomBytes(16);
        std::vector<unsigned char> key, iv;
        if (!CryptoEngine::deriveKey(password, salt, key, iv)) {
            std::cerr << "Key derivation failed.\n";
            return 1;
        }

        std::vector<unsigned char> ciphertext;
        if (!engine.encrypt(plaintext, key, iv, ciphertext)) {
            std::cerr << "Encryption failed.\n";
            return 1;
        }

        // Calculate Hashes
        std::string sha256Hex = CryptoEngine::calculateSHA256(plaintext);
        std::string md5Hex = CryptoEngine::calculateMD5(plaintext);
        
        std::cout << "Original SHA-256: " << sha256Hex << "\n";
        std::cout << "Original MD5: " << md5Hex << "\n";

        // Create human-readable header
        std::stringstream ss;
        ss << "--- SecureCrypt Encrypted File ---\n";
        ss << "Algorithm: AES-256-CBC\n";
        ss << "Original-SHA256: " << sha256Hex << "\n";
        ss << "Original-MD5: " << md5Hex << "\n";
        ss << "Salt-B64: " << CryptoEngine::base64Encode(salt) << "\n";
        ss << "IV-B64: " << CryptoEngine::base64Encode(iv) << "\n";
        
        std::vector<unsigned char> checksum;
        for (size_t i = 0; i < sha256Hex.length(); i += 2) {
            std::string byteString = sha256Hex.substr(i, 2);
            checksum.push_back(static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16)));
        }
        ss << "Checksum-B64: " << CryptoEngine::base64Encode(checksum) << "\n";
        ss << "Data-B64: " << CryptoEngine::base64Encode(ciphertext) << "\n";
        ss << "--- End SecureCrypt File ---\n";

        std::string output = ss.str();
        std::vector<unsigned char> outputData(output.begin(), output.end());

        std::string outPath = filePath + ".enc";
        if (FileManager::writeFile(outPath, outputData)) {
            std::cout << "Success! File saved to " << outPath << "\n";
        } else {
            std::cerr << "Failed to write output file.\n";
            return 1;
        }

    } else if (mode == "decrypt") {
        std::cout << "Decrypting " << filePath << "...\n";

        auto data = FileManager::readFile(filePath);
        std::string content(data.begin(), data.end());
        
        if (content.find("--- SecureCrypt Encrypted File ---") == std::string::npos) {
            std::cerr << "Error: Not a valid SecureCrypt text-encrypted file.\n";
            return 1;
        }

        auto getField = [&](const std::string& key) -> std::string {
            size_t start = content.find(key + ": ");
            if (start == std::string::npos) return "";
            start += key.length() + 2;
            size_t end = content.find("\n", start);
            return content.substr(start, end - start);
        };

        std::string saltB64 = getField("Salt-B64");
        std::string ivB64 = getField("IV-B64");
        std::string checksumB64 = getField("Checksum-B64");
        std::string dataB64 = getField("Data-B64");

        if (saltB64.empty() || ivB64.empty() || dataB64.empty()) {
            std::cerr << "Error: Missing required fields in encrypted file.\n";
            return 1;
        }

        std::vector<unsigned char> salt = CryptoEngine::base64Decode(saltB64);
        std::vector<unsigned char> iv = CryptoEngine::base64Decode(ivB64);
        std::vector<unsigned char> storedChecksum = CryptoEngine::base64Decode(checksumB64);
        std::vector<unsigned char> ciphertext = CryptoEngine::base64Decode(dataB64);

        std::vector<unsigned char> key, derivedIv;
        if (!CryptoEngine::deriveKey(password, salt, key, derivedIv)) {
            std::cerr << "Key derivation failed.\n";
            return 1;
        }

        std::vector<unsigned char> plaintext;
        if (!engine.decrypt(ciphertext, key, iv, plaintext)) {
            std::cerr << "Decryption failed. Wrong password or corrupted file.\n";
            return 1;
        }

        // Verify Integrity
        std::string currentSHA256 = CryptoEngine::calculateSHA256(plaintext);
        std::string currentMD5 = CryptoEngine::calculateMD5(plaintext);
        
        std::cout << "Decrypted SHA-256: " << currentSHA256 << "\n";
        std::cout << "Decrypted MD5: " << currentMD5 << "\n";

        std::string outPath = filePath;
        if (outPath.size() > 4 && outPath.substr(outPath.size() - 4) == ".enc") {
            outPath = outPath.substr(0, outPath.size() - 4);
        } else {
            outPath += ".dec";
        }

        if (FileManager::writeFile(outPath, plaintext)) {
            std::cout << "Success! File saved to " << outPath << "\n";
        } else {
            std::cerr << "Failed to write output file.\n";
            return 1;
        }
    } else {
        printUsage();
        return 1;
    }

    return 0;
}
