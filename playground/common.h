#pragma once

#include <stddef.h>
#include <stdint.h>

#if _DEBUG

#ifdef NDEBUG
#error "NDEBUG defined the same time as (_DEBUG || DEBUG)."
#endif

#define ASSERT(x) ((x) ? (void)0 : __debugbreak())
#else
#define ASSERT(e) ((void)0)
#endif

// Like ASSERT(x), but not compiled out in any build:
#define Verify(x)        ((x) ? (void)0 : __debugbreak())

// Implemented(x): same as Verify(x) but the reason is the code may not yet handle cases where x isn't true.
#define Implemented(x) ((x) ? (void)0 : __debugbreak())

#if defined _MSC_VER
#define ASSUME(x)     (ASSERT(x), __assume(x))
#define unreachable   (ASSERT(0), __assume(0))
#define forceinline   __forceinline
#define outline       __declspec(noinline)
#define noreturn_void __declspec(noreturn) void
#define MSVC_PRAGMA(...) __pragma(__VA_ARGS__)
extern "C" {
    unsigned char _BitScanReverse(unsigned long* Index, unsigned long Mask);
    unsigned char _BitScanReverse64(unsigned long* Index, unsigned __int64 Mask);

    unsigned char _BitScanForward(unsigned long* Index, unsigned long Mask);
    unsigned char _BitScanForward64(unsigned long* Index, unsigned __int64 Mask);
} // extern "C"
__forceinline int bsr(unsigned long v) { unsigned long i; _BitScanReverse(&i, v); return i; }
__forceinline int bsf(unsigned long v) { unsigned long i; _BitScanForward(&i, v); return i; }
#elif defined __GNUC__
#define ASSUME(x)     ASSERT(x)
#define unreachable   (ASSERT(0), __builtin_unreachable())
#define forceinline   __attribute__((always_inline))
#define outline       __attribute__((noinline))
#define noreturn_void __attribute__((noreturn)) void
#define bsr32(v)      (__builtin_clz(v) ^ 31)
#define MSVC_PRAGMA(...)
#else
#define ASSUME(x)     ASSERT(x)
#define unreachable   ASSERT(0)
#define forceinline
#define outline
#define noreturn_void void
#define MSVC_PRAGMA(...)
#endif

//    0  -> undef
//    1  -> 0
//    2  -> 1
// [3:4] -> 2
// [5:8] -> 3
// ...
inline uint32_t CeilLog2(uint32_t x)
{
    uint32_t xm1 = x - 1;
    return xm1 ? bsr(xm1) + 1 : 0;
}

typedef unsigned int uint;
typedef unsigned char ubyte;

template<class T, unsigned N> char(&_helper_countof(const T(&)[N]))[N];

#define                                    countof(a) unsigned(sizeof _helper_countof(a))
template<class T, unsigned N> constexpr T* endof(T(&a)[N]) { return a + N; }

// T should be trivial/small.
// If inputs are equal or unordered:
// - Min() returns LHS
// - Max() returns RHS, what Min() wouldn't return.
template<class T> T Min(T a, T b) { return b < a ? b : a; } // float: minss b, a
template<class T> T Max(T a, T b) { return b < a ? a : b; } // float: maxss a, b

inline bool HasTwoOrMoreBits(uint32_t v) { return (v & (v - 1)) != 0; }
// Called this instead of "IsPowerOf2" since INT_MIN isn't exactly a power of 2:
inline bool HasOneBit(uint32_t v) { return (v & (v - 1)) == 0 && (v != 0); }

template<class DstT, class SrcT>
DstT TruncateAsserted(SrcT s)
{
    static_assert(sizeof(DstT) < sizeof(SrcT),
        "DstT should be smaller than SrcT to avoid pootentially misleading code.");
    DstT d = DstT(s);
    ASSERT(SrcT(d) == s); // Assert round-trips. Should maybe do memcmp for floating-point.
    return d;
}

template<class T>
struct view {
    T* ptr;
    uint length;

    // ranged for:
    T* begin() const { return ptr; }
    T* end() const { return ptr + length; }

    bool empty() const { return length == 0; }

    T& operator[](uint i) const { ASSERT(i < length); return ptr[i]; }
};

// The count on input does not include the '\0' terminator:
inline constexpr view<const char> operator""_view(const char* strlit, size_t n)
{
    return { strlit, uint(n) };
}

#define BytePtrSub(a, b) (reinterpret_cast<const char *>(a) - reinterpret_cast<const char *>(b))

#define IsSuperset(a, b) ( !( (b) & ~(a) ) )

#define BitsPerByte 8
