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
        Content_Checksum_flag   = 1 << 2,
        // Reserved_bit         = 1 << 3,   // must be zero in current spec
        // Unused_bit           = 1 << 4,   // user-data bit
        Single_Segment_flag     = 1 << 5,
    };
};

struct Context {
    const uint8_t* srcGlobalEnd;
    uint8_t*       dstGlobalCap;
    const uint8_t* srcCurrentBlockEnd;
    uint8_t*       dstCurrentFrameExpectedEndOrGlobalCap;
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
    // Normal "float" e5m3 encoding. Like TLSF but with bias.
    uint const Mantissa = Window_Descriptor & 0x7;
    uint const Exponent = Window_Descriptor >> 3; // biased
    return supported_window_size_t(0x8 | Mantissa) << (Exponent + 7);
}
static_assert(MaxSupportedWindowSize == DecodeWindowSize(MaxSupportedWindowDescriptor), "");

enum : ptrdiff_t {
    // NOTE: the negative values of these are returned.
    decode_error_generic = 1,
    decode_error_unsupported_window_size,
    decode_error_unsupported_dictionary,
};



ptrdiff_t jw_zstd_decompress(uint8_t* dst, size_t _dstCapacity, const uint8_t* src, size_t _srcSize)
{
    Context ctx = {};
    ctx.dstGlobalCap = dst + _dstCapacity;
    ctx.srcGlobalEnd = src + _srcSize;

    uint8_t* const dstBase = dst;

    while (src < ctx.srcGlobalEnd) {
        // Deal with frame magic or skippable frames.
        if ((ctx.srcGlobalEnd - src) >= 4) {
            uint32_t const frameMagic = loadu(uint32_t, src);
            if ((frameMagic & -16) == 0x184D2A50) {
                // skippable frame
                src += 4;
                ValidData((ctx.srcGlobalEnd - src) >= 4);
                uint32_t const Frame_Size = loadu_postinc(uint32_t, src); // of the following payload
                ValidData((ctx.srcGlobalEnd - src) >= Frame_Size);
                src += Frame_Size;
                continue;
            // Not sure if the 0xFD2FB528 ZSTD frame magic is optional in some legacy formats.
            // This should be okay since Reserved_bit must be zero and is bit 3 (8 == (1 << 3)).
            } else if (frameMagic == 0xFD2FB528) {
                src += 4;
            }
        }

        // Unpack frame header.
        Frame_Header::Flags const Frame_Header_Descriptor = Frame_Header::Flags(*src++);
        if (Frame_Header_Descriptor & 0x8) // Reserved_bit
            return -decode_error_generic;
        supported_window_size_t Window_Size = 0; // might be updated to Frame_Content_Size later
        if (!(Frame_Header_Descriptor & Frame_Header::Single_Segment_flag)) {
            uint8_t const Window_Descriptor = *src++;
            if (MaxSupportedWindowDescriptor < Window_Descriptor)
                return -decode_error_unsupported_window_size;
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
        if (Dictionary_ID != 0)
            return -decode_error_unsupported_dictionary; // unsupported by us
        uint64_t Frame_Content_Size; // original (uncompressed) size, OPTIONAL, 0=unknown
        switch (Frame_Header_Descriptor >> 6) {
            case 0:
                if (!(Frame_Header_Descriptor & Frame_Header::Single_Segment_flag))
                    Frame_Content_Size = 0;
                else
                    Frame_Content_Size = loadu_postinc(uint8_t,  src);
                break;
            case 1: Frame_Content_Size = loadu_postinc(uint16_t, src) + 256; break;
            case 2: Frame_Content_Size = loadu_postinc(uint32_t, src);       break;
            case 3: Frame_Content_Size = loadu_postinc(uint64_t, src);       break;
            default: unreachable;
        }
        if (Frame_Header_Descriptor & Frame_Header::Single_Segment_flag) {
            if (MaxSupportedWindowSize < Frame_Content_Size) {
                return -decode_error_unsupported_window_size;
            }
            Window_Size = uint32_t(Frame_Content_Size);
        }
        ctx.dstCurrentFrameExpectedEndOrGlobalCap = Frame_Content_Size ? dst + Frame_Content_Size : ctx.dstGlobalCap;

        uint8_t *const dstFrameDecompressedBase = dst;
        for (;;) {
            const uint32_t Block_Header = src[0] | uint32_t(src[1]) << 8 | uint32_t(src[2]) << 16;
            src += 3;
            const uint8_t *const Block_Content = src;
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
                ctx.srcCurrentBlockEnd = Block_Content + blockContentSize;
                ptrdiff_t res = (Implemented(0), 0); // TODO
                if (res < 0)
                    return res;
                dst += res;
            }

            if (Block_Header & 1) // Last_Block
                break;
        }

        size_t const decompressedFrameSize = dst - dstFrameDecompressedBase;
        ValidData(Frame_Content_Size == 0 || Frame_Content_Size >= decompressedFrameSize);

        if (Frame_Header_Descriptor & Frame_Header::Content_Checksum_flag) {
            ValidData((ctx.srcGlobalEnd - src) >= 4);
            if (1) {
                const uint32_t expectedChecksum = loadu(uint32_t, src);
                const uint32_t gotChecksum = CalculateZstdFrameChecksum(dstFrameDecompressedBase, decompressedFrameSize);
                ValidData(expectedChecksum == gotChecksum);
            }
            src += 4;
        }
    }

    Verify(src == ctx.srcGlobalEnd);
    Verify(ctx.dstGlobalCap >= dst);
    return dst - dstBase;
}

/*
zstd\playground\data> ..\zstd-jw\x64\Debug\zstd-jw.exe bin2c C:\ice\untracked\zstd\playground\data\empty.txt.zst
*/
static constexpr uint8_t Empty_zst[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51
};

// playground\data> ..\zstd-jw\x64\Debug\zstd-jw.exe bin2c C:\ice\untracked\zstd\playground\data\ABC.txt.zst
static constexpr uint8_t ABC_zst[] = {
    0x28,0xb5,0x2f,0xfd,0x24,0x03,0x19,0x00,0x00,0x41,0x42,0x43,0x98,0xee,0xcf,0x4f,
};

#if 0 // it doesn't use RLE for this, will have to construct myself. Add basic file utilites (write/slurp).
playground\data> ..\zstd-jw\x64\Debug\zstd-jw.exe bin2c C:\ice\untracked\zstd\playground\data\Ax256.txt.zst
static constexpr uint8_t Ax256_zst[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x64, 0x00, 0x00, 0x4d, 0x00, 0x00, 0x10, 0x41, 0x41, 0x01, 0x00, 0x7b,
    0x0a, 0x60, 0x01, 0x22, 0x7b, 0x35, 0x4d
};
#endif

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
                    printf("0x%02x,", bytes[i + j]);
                    if (++j == nline)
                        break;
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

    {
        uint8_t dstbuf[2000];
        ptrdiff_t result = jw_zstd_decompress(dstbuf, countof(dstbuf), ABC_zst, countof(ABC_zst));
        Verify(result == 3);
        Verify(memcmp(dstbuf, "ABC", 3) == 0);
    }

    puts("Bye.");
    return 0;
}
