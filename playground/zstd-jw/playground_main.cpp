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
    enum {
        // Has Dictionary_ID if nonzero:
        HasDictionaryID_multiflag = _x_Dictionary_ID_flag0 |
                                    _x_Dictionary_ID_flag1,
    };

    uint16_t    magicAndHeaderPackedSize;
    Flags       flags;

    uint32_t    Dictionary_ID;

    uint64_t    Window_Size;
    uint64_t    Frame_Content_Size; // original (uncompressed) size, OPTIONAL, 0=unknown
};


static Frame_Header UnpackMagicAndFrameHeader(const uint8_t* p, bool magicless)
{
    Frame_Header h;

    const uint8_t* const pBase = p;
    if (!magicless) {
        ValidData(loadu(uint32_t, p) == 0xFD2FB528);
        p += 4;
    }
    Frame_Header::Flags const Frame_Header_Descriptor = Frame_Header::Flags(*p++);
    h.flags = Frame_Header_Descriptor;

    bool const ss = Frame_Header_Descriptor & Frame_Header::Single_Segment_flag;

    int fcsFieldSizeLog2 = Frame_Header_Descriptor >> 6;
    if (fcsFieldSizeLog2 == 0) {
        fcsFieldSizeLog2 = ss ? 0 : -1; // (desc >> 5) - 1
    }

    uint64_t Window_Size = 0;
    if (!ss) {
        uint8_t const Window_Descriptor = *p++;
        uint const Mantissa   = Window_Descriptor & 0x7;
        uint const Exponent   = Window_Descriptor >> 3;

        uint const windowLog      = 10 + Exponent; // in [10:41]
        uint64_t const windowBase = uint64_t(1) << windowLog;
        uint64_t const windowAdd  = (windowBase / 8) * Mantissa;
        Window_Size               = windowBase + windowAdd;
    }
    else {
        // Window_Size = Frame_Content_Size, latter must be present
        ValidData(fcsFieldSizeLog2 >= 0);
    }

    uint32_t did;
    switch (Frame_Header_Descriptor & Frame_Header::HasDictionaryID_multiflag) {
        case 0: did = 0;                          break;
        case 1: did = loadu_postinc(uint8_t,  p); break;
        case 2: did = loadu_postinc(uint16_t, p); break;
        case 3: did = loadu_postinc(uint32_t, p); break;
        default: unreachable;
    }
    h.Dictionary_ID = did;

    uint64_t fcs;
    switch (fcsFieldSizeLog2) {
        case -1: fcs = 0;                                break;
        case  0: fcs = loadu_postinc(uint8_t, p);        break;
        case  1: fcs = loadu_postinc(uint16_t, p) + 256; break;
        case  2: fcs = loadu_postinc(uint32_t, p);       break;
        case  3: fcs = loadu_postinc(uint64_t, p);       break;
        default: unreachable;
    }
    h.Frame_Content_Size = fcs;

    Window_Size = ss ? fcs : Window_Size;
    h.Window_Size = Window_Size;

    h.magicAndHeaderPackedSize = uint16_t(p - pBase);
    return h;
}

enum Block_Type_enum {
    Raw_Block,
    RLE_Block,
    Compressed_Block
};

size_t jw_zstd_decompress(uint8_t* dst, size_t _dstCapacity, const uint8_t* src, size_t _srcSize)
{
          uint8_t* const dstBase   = dst;
          uint8_t* const dstCapPtr = dst + _dstCapacity;
    const uint8_t* const srcCapPtr = src + _srcSize;

    for (;;) {
        ValidData((srcCapPtr - src) >= 4 + 2);
        const Frame_Header h = UnpackMagicAndFrameHeader(src, false);
        src += h.magicAndHeaderPackedSize;

        uint8_t *const dstFrameDecompressedBase = dst;

        for (;;) {
            const uint32_t Block_Header = src[0] | uint32_t(src[1]) << 8 | uint32_t(src[2]) << 16;
            src += 3;
            // const uint8_t *const srcBlockContentBase = src;

            const Block_Type_enum Block_Type = Block_Type_enum(Block_Header >> 1 & 0x3);
            uint32_t blockContentSize = Block_Header >> 3; // not final for RLE_block
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
            }

            if (Block_Header & 1) // Last_Block
                break;
        }

        if (h.flags & Frame_Header::Content_Checksum_flag) {
            const uint32_t expectedChecksum = loadu_postinc(uint32_t, src);
            const uint32_t gotChecksum = CalculateZstdFrameChecksum(dstFrameDecompressedBase, dst - dstFrameDecompressedBase);
            ValidData(expectedChecksum == gotChecksum);
        }

        if (src >= srcCapPtr) {
            Verify(src == srcCapPtr);
            Verify(dstCapPtr >= dst);
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
