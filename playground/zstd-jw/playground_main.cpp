#include "common.h"
#include "pcg.h"

#include <stdio.h>

int main()
{
#if 0
    {
        // try to generate a Raw_Block
        uint8_t buf[256];
        for (uint i = 0; i < countof(buf); ++i)
            buf[i] = TruncateAsserted<uint8_t>(i);
        pcg32_random_t rng = PCG32_INITIALIZER;
        Shuffle(buf, countof(buf), &rng);
        FILE* fp = fopen("rand256.bin", "wb");
        fwrite(buf, sizeof(buf[0]), countof(buf), fp);
        fclose(fp);
    }
#endif

    puts("Hello World!");
    return 0;
}
