#pragma once

// ============================================================
// kli_seed.hpp — KliProtected 第 1 层: 内联属性宏 + 编译期种子 (meta/seed)
// ============================================================
// 自 KliProtected.hpp 拆出 (原样搬运); 仅由伞文件按序 include。

// =======================================================================
//  基础设施: 内联属性宏 + 编译期辅助
// =======================================================================

#ifdef _MSC_VER
#define KLI_FORCEINLINE __forceinline
#define KLI_NOINLINE    __declspec(noinline)
#else
#define KLI_FORCEINLINE __attribute__((always_inline))
#define KLI_NOINLINE    __attribute__((noinline))
#endif

namespace KliProtected {
namespace meta {
    template<size_t... I> struct index_seq {};
    template<size_t N, size_t... I> struct make_seq : make_seq<N - 1, N - 1, I...> {};
    template<size_t... I> struct make_seq<0, I...> { using type = index_seq<I...>; };
    template<size_t N> using make_index_sequence_t = typename make_seq<N>::type;
} // namespace meta
} // namespace KliProtected

// =======================================================================
//  种子与伪随机
// =======================================================================

namespace KliProtected {
namespace seed {

    constexpr uint32_t cx_seed(uint32_t tag) {
        uint32_t s = tag | 1;
        s = (s << 13) | (s >> 19);
        s ^= s >> 17;
        s += s << 3;
        s ^= s >> 13;
        s += s << 7;
        s ^= s >> 16;
        return s | 1;
    }

    // 编译期派生常量
    constexpr uint32_t FNV1A_OFFSET32 = cx_seed(0xF0);
    constexpr uint32_t FNV1A_PRIME32 = cx_seed(0xF1) | 1;
    constexpr uint32_t MURMUR3_C1 = cx_seed(0xA1) | 1;
    constexpr uint32_t MURMUR3_C2 = cx_seed(0xA2) | 1;
    constexpr uint32_t IRREVERSIBLE_SALT = cx_seed(0xB1);

    // 编译环境熵
    constexpr uint32_t file_hash() {
        uint32_t h = FNV1A_OFFSET32;
        h ^= _MSC_VER;      h *= FNV1A_PRIME32;
        h ^= _MSC_FULL_VER; h *= FNV1A_PRIME32;
        h ^= __COUNTER__;   h *= FNV1A_PRIME32;
        h ^= _MSC_VER >> 8; h *= FNV1A_PRIME32;
        h ^= _MSC_FULL_VER >> 16; h *= FNV1A_PRIME32;
        return h;
    }

    // ARX 混合, 返回奇数
    constexpr uint32_t mix(uint32_t s, uint32_t tag) {
        uint32_t v = s + tag;
        v = (v << 13) | (v >> 19);
        v ^= v >> 17;
        v += v << 3;
        v ^= v >> 13;
        v += v << 7;
        v ^= v >> 16;
        return v | 1;
    }

    constexpr uint64_t mix64(uint32_t s, uint32_t tag) {
        return (static_cast<uint64_t>(mix(s, tag + 1)) << 32) | mix(s, tag);
    }

    // Murmur 风格混合, 返回奇数
    constexpr uint32_t mix_b(uint32_t s, uint32_t tag) {
        uint32_t v = s ^ tag;
        v *= MURMUR3_C1;
        v = (v << 17) | (v >> 15);
        v *= MURMUR3_C2;
        v ^= v >> 16;
        return v | 1;
    }

    // 基于 __TIME__/__DATE__ 的编译期种子
    constexpr uint32_t time_seed() {
        uint32_t t = static_cast<uint32_t>(__TIME__[7]) ^
            (static_cast<uint32_t>(__TIME__[6]) << 4) ^
            (static_cast<uint32_t>(__TIME__[4]) << 8) ^
            (static_cast<uint32_t>(__TIME__[3]) << 16) ^
            (static_cast<uint32_t>(__TIME__[1]) << 20) ^
            (static_cast<uint32_t>(__TIME__[0]) << 24);
        uint32_t d = static_cast<uint32_t>(__DATE__[4]) ^
            (static_cast<uint32_t>(__DATE__[5]) << 8) ^
            (static_cast<uint32_t>(__DATE__[8]) << 16) ^
            (static_cast<uint32_t>(__DATE__[9]) << 24) ^
            (static_cast<uint32_t>(__DATE__[0]) << 5) ^
            (static_cast<uint32_t>(__DATE__[1]) << 13);
        t ^= d;
        t ^= static_cast<uint32_t>(_MSC_VER);
        t ^= static_cast<uint32_t>(_MSC_FULL_VER) >> 16;
        t = (t << 7) | (t >> 25);
        t ^= t >> 17;
        t = (t << 13) | (t >> 19);
        t ^= t >> 11;
        uint64_t salt = 0;
        salt  = static_cast<uint64_t>(__TIME__[7] ^ __DATE__[4]) << 56;
        salt |= static_cast<uint64_t>(__TIME__[4] ^ __DATE__[9]) << 48;
        salt |= static_cast<uint64_t>(__TIME__[1] ^ __DATE__[5]) << 40;
        salt |= static_cast<uint64_t>(__TIME__[6] ^ __DATE__[8]) << 32;
        salt |= static_cast<uint64_t>(__TIME__[3] ^ __DATE__[0]) << 24;
        salt |= static_cast<uint64_t>(__TIME__[0] ^ __DATE__[1]) << 16;
        salt |= static_cast<uint64_t>(__DATE__[3] ^ __TIME__[6]) << 8;
        salt |= static_cast<uint64_t>(__DATE__[7] ^ __TIME__[1]);
        salt ^= static_cast<uint64_t>(_MSC_VER) << 48;
        salt ^= static_cast<uint64_t>(_MSC_FULL_VER & 0xFFFF) << 32;
        salt ^= (salt >> 17) ^ (salt >> 35);
        salt  = (salt << 31) | (salt >> 33);
        salt ^= (salt >> 23);
        salt  = (salt << 27) | (salt >> 37);
        salt ^= (salt >> 17);
        t ^= static_cast<uint32_t>(salt);
        t = (t << 17) | (t >> 15);
        t ^= t >> 13;
        t ^= static_cast<uint32_t>(salt >> 32);
        t = (t << 11) | (t >> 21);
        t ^= file_hash();
        t = (t << 15) | (t >> 17);
        t ^= t >> 11;
        return t | 1;
    }

    // 类型特征辅助
    template<typename T, typename U> struct TypeMatch { static constexpr bool value = false; };
    template<typename T> struct TypeMatch<T, T> { static constexpr bool value = true; };

} // namespace seed
} // namespace KliProtected