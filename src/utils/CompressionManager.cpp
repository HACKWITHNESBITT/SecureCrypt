#include "CompressionManager.h"
#include <zlib.h>
#include <stdexcept>

namespace SecureCrypt::Utils {

bool CompressionManager::compress(const std::vector<unsigned char>& input, std::vector<unsigned char>& output) {
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK) return false;

    zs.next_in = const_cast<Bytef*>(input.data());
    zs.avail_in = input.size();

    int ret;
    char outbuffer[32768];

    output.clear();
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = deflate(&zs, Z_FINISH);

        if (output.size() < zs.total_out) {
            output.insert(output.end(), outbuffer, outbuffer + (zs.total_out - output.size()));
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);

    return ret == Z_STREAM_END;
}

bool CompressionManager::decompress(const std::vector<unsigned char>& input, std::vector<unsigned char>& output) {
    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (inflateInit(&zs) != Z_OK) return false;

    zs.next_in = const_cast<Bytef*>(input.data());
    zs.avail_in = input.size();

    int ret;
    char outbuffer[32768];

    output.clear();
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, Z_SYNC_FLUSH);

        if (output.size() < zs.total_out) {
            output.insert(output.end(), outbuffer, outbuffer + (zs.total_out - output.size()));
        }
    } while (ret == Z_OK);

    inflateEnd(&zs);

    return ret == Z_STREAM_END;
}

} // namespace SecureCrypt::Utils
