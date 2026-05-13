#include "FileManager.h"
#include <fstream>
#include <iterator>
#include <filesystem>
#include <random>

namespace SecureCrypt::File {

std::vector<unsigned char> FileManager::readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return {};

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)),
                                      std::istreambuf_iterator<char>());
}

bool FileManager::writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

bool FileManager::secureDelete(const std::string& path) {
    if (!exists(path)) return false;

    size_t size = getFileSize(path);
    std::ofstream file(path, std::ios::binary | std::ios::out);
    if (!file.is_open()) return false;

    // Overwrite with random data
    std::vector<unsigned char> buffer(4096);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    size_t written = 0;
    while (written < size) {
        for (auto& b : buffer) b = static_cast<unsigned char>(dis(gen));
        size_t toWrite = std::min(buffer.size(), size - written);
        file.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
        written += toWrite;
    }
    file.close();

    return std::filesystem::remove(path);
}

bool FileManager::exists(const std::string& path) {
    return std::filesystem::exists(path);
}

size_t FileManager::getFileSize(const std::string& path) {
    return std::filesystem::file_size(path);
}

} // namespace SecureCrypt::File
