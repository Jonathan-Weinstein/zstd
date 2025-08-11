#include <stdint.h>
#include <stdlib.h> // msvc _byteswap_ulong
#define XXH_NO_STREAM
#define XXH_IMPLEMENTATION
#include "..\lib\common\xxhash.h"

uint32_t CalculateZstdFrameChecksum(const uint8_t* decompressedFrame, size_t nbytes)
{
    uint64_t q = XXH64(decompressedFrame, nbytes, 0);
    return uint32_t(q);
}
