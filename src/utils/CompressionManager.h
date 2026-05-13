#pragma once

#include <vector>
#include <string>

namespace SecureCrypt::Utils {

class CompressionManager {
public:
    /**
     * @brief Compresses data using zlib.
     */
    static bool compress(const std::vector<unsigned char>& input, std::vector<unsigned char>& output);

    /**
     * @brief Decompresses data using zlib.
     */
    static bool decompress(const std::vector<unsigned char>& input, std::vector<unsigned char>& output);
};

} // namespace SecureCrypt::Utils
