#pragma once

// ============================================================
// kli_runtime.hpp — KliProtected 第 3 层: 导出表解析 + 哈希 + 会话密钥
// ============================================================
// (namespace KliProtected: detail / hash / Runtime)
// 自 KliProtected.hpp 拆出 (原样搬运); 仅由伞文件按序 include。

namespace KliProtected {
// =======================================================================
//  内部实现: PE 解析 / 导出表
// =======================================================================

namespace detail {

    constexpr uint64_t KERN_ADDR_MIN = ~0ULL << 47;
    constexpr uint64_t KERN_ADDR_MAX = ~0ULL;

    // ── 导出表解析 (纯偏移访问, 偏移通过 obf_const 运行时解码) ──

    struct ExportTableInfo {
        uintptr_t export_dir_base;
        uint32_t* names;
        uint16_t* ordinals;
        uint32_t* functions;
        uint32_t export_rva_start;
        uint32_t export_rva_end;
    };

    // PE 导出表解析: 模板化按 Counter 实例化, 每调用点独立 codegen
    template<uint32_t Counter>
    KLI_FORCEINLINE bool parse_pe_export_table(uintptr_t base, ExportTableInfo* out) {
        auto off = obf_const::pe_off();
        if (*reinterpret_cast<volatile uint16_t*>(base + off.dos_magic) != obf_const::dos_sig()) return false;
        int32_t e_lfanew = *reinterpret_cast<volatile int32_t*>(base + off.dos_lfanew);
        if (e_lfanew <= 0 || static_cast<uint32_t>(e_lfanew) > 0x10000000) return false;
        if (*reinterpret_cast<volatile uint32_t*>(base + e_lfanew + off.pe_sig) != obf_const::pe_sig()) return false;

        uintptr_t datadir_addr = base + e_lfanew + 4 + 20 + off.oh_datadir + off.dir_export * off.sizeof_datadir_entry;
        uint32_t dir_va  = *reinterpret_cast<volatile uint32_t*>(datadir_addr);
        uint32_t dir_size = *reinterpret_cast<volatile uint32_t*>(datadir_addr + 4);
        if (!dir_va || !dir_size) return false;

        uintptr_t exp_base = base + dir_va;
        uint32_t num_names = *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_numnames);
        uint32_t addr_names = *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_addrofnames);
        if (!num_names || !addr_names) return false;

        // 编译期分叉: 不同 Counter 字段读取顺序不同, 抗模式聚类
        out->export_dir_base = exp_base;
        out->names = reinterpret_cast<uint32_t*>(base + addr_names);
        out->export_rva_start = dir_va;
        out->export_rva_end = dir_va + dir_size;
        if constexpr ((seed::cx_seed(Counter) & 1) == 0) {
            out->ordinals = reinterpret_cast<uint16_t*>(base + *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_addrofnameordinals));
            out->functions = reinterpret_cast<uint32_t*>(base + *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_addroffunctions));
        }
        else {
            out->functions = reinterpret_cast<uint32_t*>(base + *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_addroffunctions));
            out->ordinals = reinterpret_cast<uint16_t*>(base + *reinterpret_cast<volatile uint32_t*>(exp_base + off.exp_addrofnameordinals));
        }
        return true;
    }

    inline uintptr_t resolve_function_rva(uintptr_t base, const ExportTableInfo& info, uint32_t ordinal_index) {
        uint32_t func_rva = info.functions[ordinal_index];
        if (func_rva >= info.export_rva_start && func_rva < info.export_rva_end) return 0;
        return base + func_rva;
    }

    constexpr uint32_t random_export_start(uint32_t count) {
        return count ? seed::mix(seed::time_seed(), 0xB1) % count : 0;
    }

    // ── 供 ClearTraces.hpp 引用 (最小化结构体, 仅模式扫描使用) ──

    struct KLI_IMAGE_DOS_HEADER {
        uint16_t e_magic;
        uint16_t _pad0[29];
        int32_t  e_lfanew;
    };

    struct KLI_IMAGE_NT_HEADERS64 {
        uint32_t Signature;
        struct {
            uint16_t Machine;
            uint16_t NumberOfSections;
            uint32_t TimeDateStamp;
            uint32_t PointerToSymbolTable;
            uint32_t NumberOfSymbols;
            uint16_t SizeOfOptionalHeader;
            uint16_t Characteristics;
        } FileHeader;
        struct {
            uint8_t _opaque[0x70]; 
            uint8_t _datadir[16 * 8];
        } OptionalHeader;
    };

} // namespace detail

// =======================================================================
//  编译期/运行时双哈希
// =======================================================================

namespace hash {

    namespace detail {

        template<typename Size, uint32_t Counter = 0> struct FnvConstants;

        template<uint32_t Counter>
        struct FnvConstants<uint32_t, Counter> {
            static KLI_FORCEINLINE constexpr uint32_t prime() {
                return seed::mix(seed::time_seed(), 0xF2 ^ Counter);
            }
        };

        template<uint32_t Counter>
        struct FnvConstants<uint64_t, Counter> {
            static KLI_FORCEINLINE constexpr uint64_t prime() {
                return seed::mix64(seed::time_seed(), 0xF2 ^ Counter);
            }
        };

        KLI_FORCEINLINE constexpr uint64_t rotl64(uint64_t v, int s) {
            return (v << s) | (v >> (64 - s));
        }

        KLI_FORCEINLINE constexpr uint32_t rotl32(uint32_t v, int s) {
            return (v << s) | (v >> (32 - s));
        }

        template<uint32_t Counter = 0>
        struct FinConstants {
            static constexpr uint64_t FIN64 = seed::mix64(seed::time_seed(), 0xC1 ^ Counter) ^ seed::mix64(seed::time_seed(), 0xC2 ^ Counter);
            static constexpr uint32_t FIN32 = seed::mix(seed::time_seed(), 0xC1 ^ Counter) ^ seed::mix(seed::time_seed(), 0xC2 ^ Counter);
        };

        template<uint32_t Counter = 0>
        KLI_FORCEINLINE constexpr void hash_w_round(uint32_t& h1, uint32_t& h2, uint8_t lo, uint8_t hi) {
            h1 ^= lo; h1 *= FnvConstants<uint32_t, Counter>::prime();
            h1 ^= hi; h1 *= FnvConstants<uint32_t, Counter>::prime();
            h2 = rotl32(h2, 5) ^ static_cast<uint32_t>(lo);
            h2 += h2 << 3;
            h2 = rotl32(h2, 5) ^ static_cast<uint32_t>(hi);
            h2 += h2 << 3;
        }

    } // namespace hash::detail

    // 强制编译期求值
    template<typename Type, Type Value>
    struct CxForce {
        static KLI_FORCEINLINE constexpr Type value() { return Value; }
    };

    // 编译期双哈希
    template<typename Type, typename Char, uint32_t Counter = 0>
    KLI_FORCEINLINE constexpr Type hash_dbl(const Char* str) {
        Type h1 = seed::mix(seed::time_seed(), 0xD1 ^ Counter);
        Type h2 = seed::mix(seed::time_seed(), 0xD2 ^ Counter);
        for (; *str != static_cast<Char>(0); ++str) {
            Type c = static_cast<Type>(*str);
            h1 ^= c;
            h1 *= detail::FnvConstants<Type, Counter>::prime();
            if constexpr (sizeof(Type) == 8) h2 = detail::rotl64(h2, 7) ^ static_cast<Type>(c);
            else h2 = detail::rotl32(h2, 5) ^ static_cast<Type>(c);
            h2 += h2 << 3;
        }
        if constexpr (sizeof(Type) == 8) return h1 ^ (h2 * detail::FinConstants<Counter>::FIN64);
        else return h1 ^ (h2 * detail::FinConstants<Counter>::FIN32);
    }

    // 编译期 ANSI 哈希 -> uint64_t
    template<uint32_t Counter = 0>
    KLI_FORCEINLINE constexpr uint64_t hash_a_cx(const char* str) {
        return hash_dbl<uint64_t, char, Counter>(str);
    }

    // 编译期 Wide 哈希 -> uint32_t
    template<uint32_t Counter = 0>
    KLI_FORCEINLINE constexpr uint32_t hash_w_cx(const wchar_t* str) {
        uint32_t h1 = seed::mix(seed::time_seed(), 0xD1 ^ Counter);
        uint32_t h2 = seed::mix(seed::time_seed(), 0xD2 ^ Counter);
        for (size_t i = 0; str[i] != L'\0'; ++i) {
            detail::hash_w_round<Counter>(h1, h2, static_cast<uint8_t>(str[i] & 0xFF), static_cast<uint8_t>((str[i] >> 8) & 0xFF));
        }
        return h1 ^ (h2 * detail::FinConstants<Counter>::FIN32);
    }

    // ── 运行时哈希 ──

    namespace rt {

        inline uint64_t hash_a(uint32_t counter, const char* str) {
            uint64_t h1 = seed::mix(seed::time_seed(), 0xD1 ^ counter);
            uint64_t h2 = seed::mix(seed::time_seed(), 0xD2 ^ counter);
            uint64_t prime = seed::mix64(seed::time_seed(), 0xF2 ^ counter);
            uint64_t fin64 = seed::mix64(seed::time_seed(), 0xC1 ^ counter) ^ seed::mix64(seed::time_seed(), 0xC2 ^ counter);
            for (; *str != static_cast<char>(0); ++str) {
                uint64_t c = static_cast<uint64_t>(static_cast<uint8_t>(*str));
                h1 ^= c;
                h1 *= prime;
                h2 = detail::rotl64(h2, 7) ^ c;
                h2 += h2 << 3;
            }
            return h1 ^ (h2 * fin64);
        }

        inline uint32_t hash_w(uint32_t counter, const wchar_t* str, uint16_t len) {
            uint32_t h1 = seed::mix(seed::time_seed(), 0xD1 ^ counter);
            uint32_t h2 = seed::mix(seed::time_seed(), 0xD2 ^ counter);
            uint32_t prime = seed::mix(seed::time_seed(), 0xF2 ^ counter);
            uint32_t fin32 = seed::mix(seed::time_seed(), 0xC1 ^ counter) ^ seed::mix(seed::time_seed(), 0xC2 ^ counter);
            for (uint16_t i = 0; i < len / sizeof(wchar_t); ++i) {
                uint8_t lo = static_cast<uint8_t>(str[i] & 0xFF);
                uint8_t hi = static_cast<uint8_t>((str[i] >> 8) & 0xFF);
                h1 ^= lo; h1 *= prime;
                h1 ^= hi; h1 *= prime;
                h2 = detail::rotl32(h2, 5) ^ static_cast<uint32_t>(lo);
                h2 += h2 << 3;
                h2 = detail::rotl32(h2, 5) ^ static_cast<uint32_t>(hi);
                h2 += h2 << 3;
            }
            return h1 ^ (h2 * fin32);
        }

    } // namespace rt

} // namespace hash

// =======================================================================
//  运行时会话密钥与哈希混淆
// =======================================================================

namespace Runtime {

    KLI_FORCEINLINE uintptr_t current_kthread() {
        return __readgsqword(obf_const::kthread_off());
    }

    // 会话密钥: 仅用 KTHREAD 地址 + 栈基/栈顶, 同线程内 100% 稳定
    KLI_NOINLINE uint64_t session_key() {
        uintptr_t kthread = current_kthread();
        uintptr_t stack_base = *reinterpret_cast<volatile uintptr_t*>(kthread + obf_const::kstack_base());
        uintptr_t stack_limit = *reinterpret_cast<volatile uintptr_t*>(kthread + obf_const::kstack_limit());
        constexpr uint64_t SK_M1 = (static_cast<uint64_t>(seed::cx_seed(0xD1)) << 32) | seed::cx_seed(0xD2);
        constexpr uint64_t SK_M2 = (static_cast<uint64_t>(seed::cx_seed(0xD3)) << 32) | seed::cx_seed(0xD4);
        constexpr uint64_t SK_M3 = (static_cast<uint64_t>(seed::cx_seed(0xD5)) << 32) | seed::cx_seed(0xD6);
        constexpr uint64_t SK_M4 = (static_cast<uint64_t>(seed::cx_seed(0xD7)) << 32) | seed::cx_seed(0xD8);
        uint64_t a = static_cast<uint64_t>(kthread);
        uint64_t b = static_cast<uint64_t>(stack_base);
        uint64_t c = static_cast<uint64_t>(stack_limit);
        a ^= (a >> 33); a *= SK_M1;
        b ^= (b >> 33); b *= SK_M2;
        c ^= (c >> 33); c *= SK_M3;
        uint64_t k = a ^ b ^ c;
        k ^= (k >> 33);
        k *= SK_M4;
        k ^= (k >> 33);
        return k | 1;
    }

    // 稳定掩码: 全运行时派生
    KLI_FORCEINLINE uint32_t stable_key_mask() {
        constexpr uint32_t SKM_M1 = seed::cx_seed(0xE1);
        constexpr uint32_t SKM_M2 = seed::cx_seed(0xE2);
        uintptr_t kthread = current_kthread();
        uintptr_t stack_base = *reinterpret_cast<volatile uintptr_t*>(kthread + obf_const::kstack_base());
        uint32_t rt = static_cast<uint32_t>(kthread ^ stack_base);
        rt ^= rt >> 16;
        rt *= SKM_M1;
        rt ^= rt >> 15;
        rt *= SKM_M2;
        rt ^= rt >> 16;
        return rt | 1;
    }

    // scramble_with: 接受外部传入的 sk, 避免循环中重复调用 session_key()
    template<uint32_t Tag = 0>
    KLI_FORCEINLINE uint64_t scramble_with(uint64_t sk, uint64_t h) {
        h = mba::x_xor<uint64_t, Tag, 1>(h, sk);
        h = (h << 17) | (h >> 47);
        h *= (static_cast<uint64_t>(static_cast<uint32_t>(sk) | 1u));
        h = mba::x_xor<uint64_t, Tag ^ 0xAA, 1>(h, (sk >> 17));
        return h;
    }

    template<uint32_t Tag = 0>
    KLI_FORCEINLINE uint32_t scramble32_with(uint64_t sk, uint32_t h) {
        h = mba::x_xor<uint32_t, Tag, 1>(h, static_cast<uint32_t>(sk));
        h = mba::x_xor<uint32_t, Tag ^ 0xBB, 1>(h, static_cast<uint32_t>(sk >> 32));
        h = (h << 9) | (h >> 23);
        h *= (static_cast<uint32_t>((sk ^ (sk >> 32)) & 0xFFFFFFFFu) | 1u);
        return h;
    }

    KLI_NOINLINE uint64_t scramble(uint64_t h) {
        return scramble_with<>(session_key(), h);
    }

    KLI_NOINLINE uint32_t scramble32(uint32_t h) {
        return scramble32_with<>(session_key(), h);
    }

} // namespace Runtime
} // namespace KliProtected