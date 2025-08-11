#pragma once

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// PCG by Melissa E. O'Neill
// Slight modifications where made here from original: https://github.com/imneme/pcg-c-basic

struct pcg_state_setseq_64 {    // Internals are *Private*.
    uint64_t state;             // RNG state.  All values are possible.
    uint64_t inc;               // Controls which RNG sequence (stream) is
    // selected. Must *always* be odd.
};
typedef struct pcg_state_setseq_64 pcg32_random_t;
// If you *must* statically initialize it, here's one.
#define PCG32_INITIALIZER   { 0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL }

void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq);
uint32_t pcg32_random_r(pcg32_random_t* rng);
uint32_t pcg32_boundedrand_r(pcg32_random_t* rng, uint32_t bound);

// pcg32_srandom_r(rng, initstate, initseq):
//     Seed the rng.  Specified in two parts, state initializer and a
//     sequence selection constant (a.k.a. stream id)
inline void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq)
{
    rng->state = 0U;
    rng->inc = (initseq << 1u) | 1u;
    pcg32_random_r(rng);
    rng->state += initstate;
    pcg32_random_r(rng);
}

// pcg32_random_r(rng)
//     Generate a uniformly distributed 32-bit random number
inline uint32_t pcg32_random_r(pcg32_random_t* rng)
{
    uint64_t oldstate = rng->state;
    rng->state = oldstate * 6364136223846793005ULL + rng->inc;
    uint32_t xorshifted = (uint32_t)(((oldstate >> 18u) ^ oldstate) >> 27u);
    int32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

// pcg32_boundedrand_r(rng, bound):
//     Generate a uniformly distributed number, r, where 0 <= r < bound
inline uint32_t pcg32_boundedrand_r(pcg32_random_t* rng, uint32_t bound)
{
    // To avoid bias, we need to make the range of the RNG a multiple of
    // bound, which we do by dropping output less than a threshold.
    // A naive scheme to calculate the threshold would be to do
    //
    //     uint32_t threshold = 0x100000000ull % bound;
    //
    // but 64-bit div/mod is slower than 32-bit div/mod (especially on
    // 32-bit platforms).  In essence, we do
    //
    //     uint32_t threshold = (0x100000000ull-bound) % bound;
    //
    // because this version will calculate the same modulus, but the LHS
    // value is less than 2^32.

    uint32_t threshold = -(int32_t)bound % bound;

    // Uniformity guarantees that this loop will terminate.  In practice, it
    // should usually terminate quickly; on average (assuming all bounds are
    // equally likely), 82.25% of the time, we can expect it to require just
    // one iteration.  In the worst case, someone passes a bound of 2^31 + 1
    // (i.e., 2147483649), which invalidates almost 50% of the range.  In
    // practice, bounds are typically small and only a tiny amount of the range
    // is eliminated.
    for (;;) {
        uint32_t r = pcg32_random_r(rng);
        if (r >= threshold)
            return r % bound;
    }
}
// end PCG
// ============================================================================


// Fisher-Yates/Knuth shuffle:
template<class T>
void Shuffle(T* deck, uint32_t n, pcg32_random_t* p_rng)
{
    static_assert(__is_trivial(T), "I don't care about std::move/etc.");

    if (n >= 2) {
        pcg32_random_t rng = *p_rng;
        do {
            uint32_t const j = pcg32_boundedrand_r(&rng, n); // result in [0, n)
            uint32_t const i = --n;
            /* swap(a[i], a[j]): */
            T const x = deck[i];
            T const y = deck[j];
            deck[i] = y;
            deck[j] = x;
        } while (n >= 2);
        *p_rng = rng;
    }
}
