#include "common.h"
#include "pcg.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// unaligned little-endian load at byte address
#define loadu(T, p) (*reinterpret_cast<const T*>(p))

#define loadu_postinc(T, p) ( *reinterpret_cast<const T*>( (static_cast<const uint8_t*&>(p) += sizeof(T)) - sizeof(T) ) )

// If x isn't true, then I don't think the compressed data is valid.
// Also see Implemented().
#define ValidData(x) Verify(x)

// in unity_xxhash.cpp:
uint32_t CalculateZstdFrameChecksum(const uint8_t* decompressedFrame, size_t nbytes);

struct Frame_Header {
    enum Flags : uint8_t {
        _x_Dictionary_ID_flag0  = 1 << 0,
        _x_Dictionary_ID_flag1  = 1 << 1,
        Content_Checksum_flag   = 1 << 2,

        Single_Segment_flag     = 1 << 5,
    };
};

struct DecodeContext {
    const uint8_t*  srcCap;
    uint8_t*        dstCap;
};

enum Block_Type_enum {
    Raw_Block,
    RLE_Block,
    Compressed_Block
};

// Support a max Window_Size of 16 MiB (means we can do u32 ops instead of u64 here).
typedef uint32_t supported_window_size_t;
enum : supported_window_size_t {
    MaxSupportedWindowDescriptor = (24 - 10) << 3,
    MaxSupportedWindowSize = 16 << 20
};
constexpr supported_window_size_t DecodeWindowSize(uint8_t Window_Descriptor)
{
    // Normal "float" encoding, e5m3. Like TLSF.
    uint const Mantissa = Window_Descriptor & 0x7;
    uint const Exponent = Window_Descriptor >> 3; // biased
    return supported_window_size_t(0x8 | Mantissa) << (Exponent + 7);
}
static_assert(MaxSupportedWindowSize == DecodeWindowSize(MaxSupportedWindowDescriptor), "");

ptrdiff_t jw_zstd_decompress(uint8_t* dst, size_t _dstCapacity, const uint8_t* src, size_t _srcSize)
{
    DecodeContext dc = {};
    dc.dstCap = dst + _dstCapacity;
    dc.srcCap = src + _srcSize;

    uint8_t* const dstBase = dst;

    for (;;) {
        ValidData((dc.srcCap - src) >= 4);
        uint32_t const frameMagic = loadu_postinc(uint32_t, src);
        if ((frameMagic & -16) == 0x184D2A50) {
            // skippable frame
            uint32_t const Frame_Size = loadu_postinc(uint32_t, src);
            ValidData((dc.srcCap - src) >= Frame_Size);
            src += Frame_Size;
            continue;
        }
        // TODO(?): Some formats may not have this legacy(?) ZSTD frame magic number.
        // Handle that maybe and don't do _postinc initially.
        if (frameMagic != 0xFD2FB528) {
            return -1;
        }

        // unpack frame header
        Frame_Header::Flags const Frame_Header_Descriptor = Frame_Header::Flags(*src++);
        supported_window_size_t Window_Size = 0; // might be updated to Frame_Content_Size later
        if (!(Frame_Header_Descriptor & Frame_Header::Single_Segment_flag)) {
            uint8_t const Window_Descriptor = *src++;
            if (MaxSupportedWindowDescriptor < Window_Descriptor)
                return -2;
            Window_Size = DecodeWindowSize(Window_Descriptor);
        }
        uint32_t Dictionary_ID;
        switch (Frame_Header_Descriptor & 0x3) {
            case 0: Dictionary_ID = 0;                            break;
            case 1: Dictionary_ID = loadu_postinc(uint8_t,  src); break;
            case 2: Dictionary_ID = loadu_postinc(uint16_t, src); break;
            case 3: Dictionary_ID = loadu_postinc(uint32_t, src); break;
            default: unreachable;
        }
        uint64_t Frame_Content_Size; // original (uncompressed) size, OPTIONAL, 0=unknown
        switch (Frame_Header_Descriptor >> 6) {
            case 0:
                if (!(Frame_Header_Descriptor & Frame_Header::Single_Segment_flag))
                    Frame_Content_Size = 0;
                else
                    Frame_Content_Size =
                        Window_Size    = loadu_postinc(uint8_t,  src);
                break;
            case 1: Frame_Content_Size = loadu_postinc(uint16_t, src) + 256; break;
            case 2: Frame_Content_Size = loadu_postinc(uint32_t, src);       break;
            case 3: Frame_Content_Size = loadu_postinc(uint64_t, src);       break;
            default: unreachable;
        }

        uint8_t *const dstFrameDecompressedBase = dst;
        for (;;) {
            const uint32_t Block_Header = src[0] | uint32_t(src[1]) << 8 | uint32_t(src[2]) << 16;
            src += 3;
            // const uint8_t *const srcBlockContentBase = src;

            const Block_Type_enum Block_Type = Block_Type_enum(Block_Header >> 1 & 0x3);
            uint32_t blockContentSize = Block_Header >> 3; // not actual for RLE_block
            if (Block_Type == Raw_Block) {
                memcpy(dst, src, blockContentSize);
                dst += blockContentSize;
                src += blockContentSize;
            }
            else if (Block_Type == RLE_Block) {
                memset(dst, *src, blockContentSize);
                dst += blockContentSize;
                src += 1;
            }
            else {
                ValidData(Block_Type == Compressed_Block);
                Implemented(0);
                ptrdiff_t res = 0; // TODO
                if (res < 0)
                    return res;
                dst += res;
            }

            if (Block_Header & 1) // Last_Block
                break;
        }

        size_t const decompressedFrameSize = dst - dstFrameDecompressedBase;
        ValidData(Frame_Content_Size == 0 || Frame_Content_Size >= decompressedFrameSize);
        // Don't really care about checksum most of the time, but still make sure to skip field (_postinc).
        if (Frame_Header_Descriptor & Frame_Header::Content_Checksum_flag) {
            const uint32_t expectedChecksum = loadu_postinc(uint32_t, src);
            const uint32_t gotChecksum = CalculateZstdFrameChecksum(dstFrameDecompressedBase, decompressedFrameSize);
            ValidData(expectedChecksum == gotChecksum);
        }

        if (src >= dc.srcCap) {
            Verify(src == dc.srcCap);
            Verify(dc.dstCap >= dst);
            return dst - dstBase;
        }
    }
}

/*
zstd\playground\data> ..\zstd-jw\x64\Debug\zstd-jw.exe bin2c C:\ice\untracked\zstd\playground\data\empty.txt.zst
*/
static constexpr uint8_t Empty_zst[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51
};

int main(int const argc, char const *const *const argv)
{
    int const                tailc = argc - 1;
    char const* const* const tailv = argv + 1;

    if (tailc >= 1)
    {
        const char* cmd = tailv[0];
        if (strcmp(cmd, "genrand") == 0)
        {
            ValidData(tailc == 1);

            // try to generate a Raw_Block
            uint8_t buf[256];
            for (uint i = 0; i < countof(buf); ++i)
                buf[i] = TruncateAsserted<uint8_t>(i);
            pcg32_random_t rng = PCG32_INITIALIZER;
            Shuffle(buf, countof(buf), &rng);
            FILE* fp = fopen("rand256.bin", "wb");
            fwrite(buf, sizeof(buf[0]), countof(buf), fp);
            fclose(fp);
            return 0;
        }
        else if (strcmp(cmd, "bin2c") == 0) {
            ValidData(tailc == 2);
            const char* inFileName = tailv[1];
            FILE* fp = fopen(inFileName, "rb");
            if (!fp) {
                perror("fopen");
                printf("<filename> <%s>\n", inFileName);
                return 1;
            }
            fseek(fp, 0, SEEK_END);
            ptrdiff_t ssize = ftell(fp);
            if (ssize < 0)
                return 1;
            size_t const size = ssize;
            rewind(fp);
            void* const mem = malloc(size);
            Verify(mem);
            fread(mem, 1, size, fp);
            fclose(fp);

            const uint8_t* const bytes = reinterpret_cast<uint8_t*>(mem);
            puts("static constexpr uint8_t __Data[] = {");
            size_t i = 0;
            while (i < size) {
                size_t nline = Min<size_t>(16u, size - i);
                fputs("    ", stdout);
                for (uint j = 0;;) {
                    ASSUME(i + j < size);
                    printf("0x%02x", bytes[i + j]);
                    if (++j == nline)
                        break;
                    fputs(", ", stdout);
                }
                fputs("\n", stdout);
                i += nline;
            }
            puts("};");
            free(mem);
            return 0;
        }
        else {
            ValidData(0);
            return 1;
        }
    }


    {
        uint8_t dstbuf[2000];
        ptrdiff_t result = jw_zstd_decompress(dstbuf, countof(dstbuf), Empty_zst, countof(Empty_zst));
        printf("result = %lld\n", result);
    }

    puts("Bye.");
    return 0;
}
