#pragma once

#include <string>
#include <vector>
#include <functional>

namespace SecureCrypt::File {

class FileManager {
public:
    using ProgressCallback = std::function<void(double)>;

    /**
     * @brief Reads a whole file into a byte vector. (Use for smaller files or testing)
     */
    static std::vector<unsigned char> readFile(const std::string& path);

    /**
     * @brief Writes a byte vector to a file.
     */
    static bool writeFile(const std::string& path, const std::vector<unsigned char>& data);

    /**
     * @brief Securely deletes a file by overwriting it with random data before removal.
     */
    static bool secureDelete(const std::string& path);

    /**
     * @brief Checks if a file exists.
     */
    static bool exists(const std::string& path);

    /**
     * @brief Gets the file size in bytes.
     */
    static size_t getFileSize(const std::string& path);
};

} // namespace SecureCrypt::File
