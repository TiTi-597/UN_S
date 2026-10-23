#pragma once

// ============================================================
// kli_api.hpp — KliProtected 第 5 层: 公开调用接口
// ============================================================
// (namespace KliProtected: RetAddrSpoof / 导出查找 / callcrypt)
// 全局宏: SPOOF_FUNC / KLI_SCOPED_* / FindBase / GetFunByExport /
// KLI_OBFUSCATE_CALL / KLI_FN / MBA_* / KLI_OBF_CONST
// 自 KliProtected.hpp 拆出 (原样搬运); 仅由伞文件按序 include。

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    short LoadCount;
    short TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

namespace KliProtected {
// =======================================================================
//  返回地址欺骗
// =======================================================================

namespace RetAddrSpoof {

    // 使用 obf_const 解码操作码, 消除硬编码立即数特征
    inline bool is_likely_ret_instruction(uintptr_t addr, uintptr_t page_base) {
        if (addr < page_base + 1) return true;
        uint8_t prev = *reinterpret_cast<volatile uint8_t*>(addr - 1);
        uint8_t lo = obf_const::pop_ret_lo();
        uint8_t hi = obf_const::pop_ret_hi();
        uint8_t leave = obf_const::leave_opcode();
        return (prev >= lo && prev <= hi) || prev == leave || prev == obf_const::nop_opcode() || prev == obf_const::ret_opcode() || prev == obf_const::int3_opcode();
    }

    class SpoofFunction {
        uintptr_t obf_original_;   // 原 RA 异或 spoof_key
        void* ret_addr_ = nullptr;
        bool active_ = false;

        // 密钥派生: 仅依赖 stable_key_mask + ret_addr_, 不在栈上存储密钥
        static constexpr uint64_t SPOOF_M1 = (static_cast<uint64_t>(seed::cx_seed(0xF1)) << 32) | seed::cx_seed(0xF2);
        static constexpr uint64_t SPOOF_M2 = (static_cast<uint64_t>(seed::cx_seed(0xF3)) << 32) | seed::cx_seed(0xF4);

        static KLI_FORCEINLINE uintptr_t derive_spoof_key(void* ret_addr) {
            uintptr_t a = reinterpret_cast<uintptr_t>(ret_addr);
            uint64_t sk = Runtime::stable_key_mask();
            uint64_t k = mba::x_xor<uint64_t, 0xF101>(mba::x_xor<uint64_t, 0xF102>(static_cast<uint64_t>(a), (sk << 32)), sk);
            k = mba::x_xor<uint64_t, 0xF103>(k, (k >> 33));
            k *= SPOOF_M1;
            k = mba::x_xor<uint64_t, 0xF104>(k, (k >> 33));
            k *= SPOOF_M2;
            k = mba::x_xor<uint64_t, 0xF105>(k, (k >> 33));
            return static_cast<uintptr_t>(k | 1);
        }

    public:
        KLI_NOINLINE SpoofFunction(void* addr) : ret_addr_(addr) {
            uintptr_t original = *reinterpret_cast<uintptr_t*>(ret_addr_);
            uintptr_t spoof_key = derive_spoof_key(addr);
            obf_original_ = mba::x_xor<uintptr_t, 0xF200>(original, spoof_key);

            // 搜索熵: 用调用点地址 + 当前 RA + stable_key_mask 派生 (不混 time_seed)
            uint32_t entropy = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(addr) ^ reinterpret_cast<uintptr_t>(_ReturnAddress()) ^ static_cast<uint32_t>(Runtime::stable_key_mask()));

            uintptr_t page_base = original & ~(uintptr_t)0xFFF;
            uintptr_t page_end = page_base + 0xFFF;
            uintptr_t spoof_target = 0;

            uint32_t strategy = seed::mix64(entropy, 0xA6) % 3;
            uint8_t sig_ret = obf_const::ret_opcode();

            if (strategy == 0) {
                // 策略 A: 从随机偏移向后搜索 ret 指令
                uintptr_t search_start = original - (seed::mix64(entropy, 0xA3) & 0x3FF);
                if (search_start < page_base) search_start = page_base;
                for (uintptr_t p = search_start; p > page_base; p--) {
                    if (*reinterpret_cast<volatile uint8_t*>(p) == sig_ret
                        && is_likely_ret_instruction(p, page_base)) {
                        spoof_target = p;
                        break;
                    }
                }
            }
            else if (strategy == 1) {
                // 策略 B: 从随机偏移向前搜索 ret 指令
                uintptr_t search_start = original + (seed::mix64(entropy, 0xA5) & 0x3FF);
                if (search_start > page_end) search_start = original;
                for (uintptr_t p = search_start; p < page_end; p++) {
                    if (*reinterpret_cast<volatile uint8_t*>(p) == sig_ret
                        && is_likely_ret_instruction(p, page_base)) {
                        if (p != original) {
                            spoof_target = p;
                            break;
                        }
                    }
                }
            }
            else {
                // 策略 C: 搜索 pop+ret 两字节序列 (操作码已混淆)
                uint8_t lo = obf_const::pop_ret_lo();
                uint8_t hi = obf_const::pop_ret_hi();
                uintptr_t scan_start = original - (seed::mix64(entropy, 0xA7) & 0x1FF);
                if (scan_start < page_base + 1) scan_start = page_base + 1;
                for (uintptr_t p = scan_start; p < page_end - 1; p++) {
                    uint8_t b0 = *reinterpret_cast<volatile uint8_t*>(p);
                    uint8_t b1 = *reinterpret_cast<volatile uint8_t*>(p + 1);
                    if (b1 == sig_ret && b0 >= lo && b0 <= hi) {
                        spoof_target = p + 1;
                        break;
                    }
                }
            }

            if (spoof_target && spoof_target != original) {
                *reinterpret_cast<uintptr_t*>(ret_addr_) = spoof_target;
                active_ = true;
            }
        }

        KLI_FORCEINLINE ~SpoofFunction() {
            if (active_) {
                *reinterpret_cast<uintptr_t*>(ret_addr_) = mba::x_xor<uintptr_t, 0xF200>(obf_original_, derive_spoof_key(ret_addr_));
            }
        }
    };

} // namespace RetAddrSpoof

// =======================================================================
//  导出函数/模块查找 (公开接口)
// =======================================================================

// noinline 共享导出搜索变体 (4 个分散函数, 按 counter 分发)
// 每个变体的循环方向/起始偏移/不透明谓词不同, 无统一可 hook 的锚点

// 变体 0: 正序搜索
KLI_NOINLINE uintptr_t search_export_v0(uint32_t counter, uintptr_t base, uint64_t scrambled_target) {
    detail::ExportTableInfo info{};
    if (!detail::parse_pe_export_table<0>(base, &info)) return 0;
    auto off = obf_const::pe_off();
    uint32_t count = *reinterpret_cast<volatile uint32_t*>(info.export_dir_base + off.exp_numnames);
    uint32_t start = detail::random_export_start(count);
    uintptr_t result = 0;
    uint64_t sk = Runtime::session_key();
    for (uint32_t j = 0; j < count; ++j) {
        uint32_t i = (start + j) % count;
        uint64_t h = Runtime::scramble_with<0>(sk, hash::rt::hash_a(counter, reinterpret_cast<const char*>(base + info.names[i])));
        uintptr_t candidate = detail::resolve_function_rva(base, info, info.ordinals[i]);
        result = (h == scrambled_target) ? candidate : result;
    }
    volatile uint32_t _op = obf_const::kthread_off() ^ obf_const::kstack_base();
    if (_op == 0) { volatile uint32_t _s = 0; (void)_s; }
    return result;
}

// 变体 1: 逆序搜索
KLI_NOINLINE uintptr_t search_export_v1(uint32_t counter, uintptr_t base, uint64_t scrambled_target) {
    detail::ExportTableInfo info{};
    if (!detail::parse_pe_export_table<1>(base, &info)) return 0;
    auto off = obf_const::pe_off();
    uint32_t count = *reinterpret_cast<volatile uint32_t*>(info.export_dir_base + off.exp_numnames);
    uint32_t start = detail::random_export_start(count);
    uintptr_t result = 0;
    uint64_t sk = Runtime::session_key();
    for (uint32_t j = 0; j < count; ++j) {
        uint32_t i = (count + start - j) % count;
        uint64_t h = Runtime::scramble_with<1>(sk, hash::rt::hash_a(counter, reinterpret_cast<const char*>(base + info.names[i])));
        uintptr_t candidate = detail::resolve_function_rva(base, info, info.ordinals[i]);
        result = (h == scrambled_target) ? candidate : result;
    }
    volatile uint32_t _op = obf_const::kstack_base() ^ obf_const::kstack_limit();
    if (_op == 0) { volatile uint32_t _s = 0; (void)_s; }
    return result;
}

// 变体 2: 正序, 从中间开始
KLI_NOINLINE uintptr_t search_export_v2(uint32_t counter, uintptr_t base, uint64_t scrambled_target) {
    detail::ExportTableInfo info{};
    if (!detail::parse_pe_export_table<2>(base, &info)) return 0;
    auto off = obf_const::pe_off();
    uint32_t count = *reinterpret_cast<volatile uint32_t*>(info.export_dir_base + off.exp_numnames);
    uint32_t start = count / 2;
    uintptr_t result = 0;
    uint64_t sk = Runtime::session_key();
    for (uint32_t j = 0; j < count; ++j) {
        uint32_t i = (start + j) % count;
        uint64_t h = Runtime::scramble_with<2>(sk, hash::rt::hash_a(counter, reinterpret_cast<const char*>(base + info.names[i])));
        uintptr_t candidate = detail::resolve_function_rva(base, info, info.ordinals[i]);
        result = (h == scrambled_target) ? candidate : result;
    }
    volatile uint32_t _op = obf_const::kthread_off() ^ obf_const::kstack_limit();
    if (_op == 0) { volatile uint32_t _s = 0; (void)_s; }
    return result;
}

// 变体 3: 逆序, 从末尾开始
KLI_NOINLINE uintptr_t search_export_v3(uint32_t counter, uintptr_t base, uint64_t scrambled_target) {
    detail::ExportTableInfo info{};
    if (!detail::parse_pe_export_table<3>(base, &info)) return 0;
    auto off = obf_const::pe_off();
    uint32_t count = *reinterpret_cast<volatile uint32_t*>(info.export_dir_base + off.exp_numnames);
    uintptr_t result = 0;
    uint64_t sk = Runtime::session_key();
    for (uint32_t j = 0; j < count; ++j) {
        uint32_t i = (count - 1 - j) % count;
        uint64_t h = Runtime::scramble_with<3>(sk, hash::rt::hash_a(counter, reinterpret_cast<const char*>(base + info.names[i])));
        uintptr_t candidate = detail::resolve_function_rva(base, info, info.ordinals[i]);
        result = (h == scrambled_target) ? candidate : result;
    }
    volatile uint32_t _op = obf_const::kstack_base() ^ obf_const::ret_opcode();
    if (_op == 0) { volatile uint32_t _s = 0; (void)_s; }
    return result;
}

// 分发函数: 按 counter % 4 选择变体
inline uintptr_t search_export_dispatch(uint32_t counter, uintptr_t base, uint64_t scrambled_target) {
    switch (counter & 3) {
    case 0: return search_export_v0(counter, base, scrambled_target);
    case 1: return search_export_v1(counter, base, scrambled_target);
    case 2: return search_export_v2(counter, base, scrambled_target);
    default: return search_export_v3(counter, base, scrambled_target);
    }
}

// KLI_FN 底层: 分散搜索, 不膨胀调用点
inline uintptr_t find_kernel_export(uintptr_t kernel_base, uint64_t export_hash, uint32_t counter) {
    if (!kernel_base) return 0;
    return search_export_dispatch(counter, kernel_base, Runtime::scramble(export_hash));
}

// GetFunByExport 底层
template<uint32_t Counter>
KLI_FORCEINLINE uint64_t resolve_export_by_hash(uint64_t base, uint64_t function_hash) {
    if (!base) return 0;
    return search_export_dispatch(Counter, static_cast<uintptr_t>(base), Runtime::scramble(function_hash));
}

// FindBase 底层
KLI_NOINLINE void* resolve_module_base_by_hash(PDRIVER_OBJECT driver_object, uint32_t name_hash, PLDR_DATA_TABLE_ENTRY* ldr_entry, uint32_t counter) {
    if (!driver_object || !driver_object->DriverSection) return nullptr;
    auto head = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);
    auto cur  = head;
    constexpr uint32_t MAX_MODULES = 1024;
    uint32_t count = 0;
    void* found = nullptr;
    PLDR_DATA_TABLE_ENTRY found_ldr = nullptr;
    uint64_t sk = Runtime::session_key();
    uint32_t target = Runtime::scramble32_with<>(sk, name_hash);
    do {
        if (cur && cur->BaseDllName.Buffer && cur->BaseDllName.Length > 0 &&
            cur->BaseDllName.MaximumLength >= cur->BaseDllName.Length &&
            reinterpret_cast<uint64_t>(cur->BaseDllName.Buffer) >= detail::KERN_ADDR_MIN &&
            reinterpret_cast<uint64_t>(cur->BaseDllName.Buffer) < detail::KERN_ADDR_MAX &&
            reinterpret_cast<uint64_t>(cur->BaseDllName.Buffer) + cur->BaseDllName.MaximumLength <= detail::KERN_ADDR_MAX)
        {
            if (Runtime::scramble32_with<>(sk, hash::rt::hash_w(counter, cur->BaseDllName.Buffer, cur->BaseDllName.Length)) == target) {
                if (cur->DllBase && reinterpret_cast<uint64_t>(cur->DllBase) >= detail::KERN_ADDR_MIN) {
                    if (!found) {
                        found = cur->DllBase;
                        found_ldr = cur;
                    }
                }
            }
        }
        auto next = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(cur->InLoadOrderLinks.Flink);
        if (!next || reinterpret_cast<uint64_t>(next) < detail::KERN_ADDR_MIN || reinterpret_cast<uint64_t>(next) >= detail::KERN_ADDR_MAX) break;
        cur = next;
    } while (cur != head && ++count < MAX_MODULES);
    if (found && ldr_entry) *ldr_entry = found_ldr;
    return found;
}

// =======================================================================
//  函数调用地址混淆 (callcrypt)
// =======================================================================

namespace callcrypt {

    enum class AlgoType : uint8_t {
        XOR_ROT,  ADD_ROT,
        XOR_MUL,  ADD_MUL,
        XOR_SWAP, ADD_NEG,
        MUL_XOR,  ROT_XOR,
        XOR_ROR,  ADD_ROL,
        XOR_BIT,  ADD_XCHG,
        ALGO_COUNT
    };

    // mod 2^8 乘法逆元 (Hensel 提升, 要求 x 为奇数)
    KLI_FORCEINLINE constexpr uint8_t mod_inv_256(uint8_t x) {
        uint8_t y = x;
        y = static_cast<uint8_t>(y * static_cast<uint8_t>(2 - x * y));
        y = static_cast<uint8_t>(y * static_cast<uint8_t>(2 - x * y));
        y = static_cast<uint8_t>(y * static_cast<uint8_t>(2 - x * y));
        return y;
    }

    // ── 密钥派生 ──

    KLI_FORCEINLINE constexpr uint32_t get_state_mask(uint32_t s) {
        return seed::mix_b(s, 0xE6);
    }

    KLI_FORCEINLINE constexpr uint32_t derive_main_key(uint32_t s, uint32_t raw_state) {
        return seed::mix(s ^ raw_state, 0xE5);
    }

    KLI_FORCEINLINE constexpr uint8_t derive_key(uint32_t s, size_t i, uint32_t main_key) {
        uint32_t k = seed::mix_b(main_key ^ static_cast<uint32_t>(i), static_cast<uint32_t>(s & 0xFF));
        return static_cast<uint8_t>(k & 0xFF);
    }

    KLI_FORCEINLINE constexpr uint32_t get_magic(uint32_t s, uint32_t idx) {
        return seed::mix(s, 0xE7 ^ idx);
    }

    KLI_FORCEINLINE constexpr uint32_t get_flow_variant(uint32_t s) {
        return seed::mix(s, 2) % 4;
    }

    KLI_FORCEINLINE constexpr uint32_t get_rebuild_variant(uint32_t s) {
        return seed::mix(s, 5) % 2;
    }

    KLI_FORCEINLINE constexpr uint8_t get_algo_xor_key(uint32_t s) {
        return static_cast<uint8_t>(seed::mix_b(s, 0xEE));
    }

    KLI_FORCEINLINE constexpr uint8_t get_perm_xor_key(uint32_t s) {
        return static_cast<uint8_t>(seed::mix_b(s, 0xEF));
    }

    // ── 置换表 ──

    KLI_NOINLINE void compute_permutation(uint32_t s, uint32_t raw_state, uint8_t* perm, size_t count) {
        for (size_t i = 0; i < count; ++i) perm[i] = static_cast<uint8_t>(i);
        uint32_t rng = seed::mix_b(s ^ raw_state, 0xE8);
        for (size_t i = count - 1; i > 0; --i) {
            rng = seed::mix(rng, static_cast<uint32_t>(i));
            uint32_t j = rng % static_cast<uint32_t>(i + 1);
            uint8_t tmp = perm[i]; perm[i] = perm[j]; perm[j] = tmp;
        }
    }

    // ── 地址重建 ──

    KLI_NOINLINE uintptr_t rebuild_address(const uint8_t* bytes, uint32_t variant) {
        if (variant == 0) {
            uintptr_t addr = 0;
            for (size_t i = 0; i < sizeof(uintptr_t); ++i)
                addr |= static_cast<uintptr_t>(bytes[i]) << (i * 8);
            return addr;
        }
        else {
            uintptr_t addr = 0;
            for (size_t i = sizeof(uintptr_t); i > 0; --i)
                addr = (addr << 8) | bytes[i - 1];
            return addr;
        }
    }

    // ── 去 switch 化解密 ──
    // 算法选择由 (Seed, Idx) 编译期决定; 每个调用点的 decode 函数中
    // 只展开一种算法的代码, 没有 12-case switch, 无法在统一位置 hook
    // 拿到全部 API 地址

    KLI_FORCEINLINE constexpr uint32_t inline_algo_pick(uint32_t s, size_t i) {
        return seed::mix(s, static_cast<uint32_t>(0xC0u + i)) % static_cast<uint32_t>(AlgoType::ALGO_COUNT);
    }

    template<uint32_t Seed, size_t Idx>
    KLI_FORCEINLINE uint8_t algo_decrypt_inline(uint8_t byte, uint8_t k) {
        constexpr uint32_t pick = inline_algo_pick(Seed, Idx);
        constexpr uint32_t T = Seed ^ static_cast<uint32_t>(Idx) ^ pick;
        if constexpr (pick == 0) {  // XOR_ROT
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            uint8_t v = static_cast<uint8_t>((byte >> r) | (byte << (8 - r)));
            return mba::x_xor<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 1) {  // ADD_ROT
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            uint8_t v = static_cast<uint8_t>((byte >> r) | (byte << (8 - r)));
            return mba::x_sub<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 2) {  // XOR_MUL
            return mba::x_xor<uint8_t, T>(byte, static_cast<uint8_t>((k * 0x9E + 0x37) & 0xFF));
        }
        else if constexpr (pick == 3) {  // ADD_MUL
            return mba::x_sub<uint8_t, T>(byte, static_cast<uint8_t>((k * 0x9E + 0x37) & 0xFF));
        }
        else if constexpr (pick == 4) {  // XOR_SWAP
            uint8_t v = static_cast<uint8_t>((byte >> 4) | (byte << 4));
            return mba::x_xor<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 5) {  // ADD_NEG
            uint8_t v = static_cast<uint8_t>(-(static_cast<int8_t>(byte)));
            return mba::x_sub<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 6) {  // MUL_XOR
            uint8_t m = mba::x_xor<uint8_t, T>(byte, mba::x_not<uint8_t, T ^ 0x1>(k));
            return static_cast<uint8_t>(m * mod_inv_256(static_cast<uint8_t>(k | 1)));
        }
        else if constexpr (pick == 7) {  // ROT_XOR
            uint8_t v = mba::x_xor<uint8_t, T>(byte, k);
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            return static_cast<uint8_t>((v >> r) | (v << (8 - r)));
        }
        else if constexpr (pick == 8) {  // XOR_ROR
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            uint8_t v = static_cast<uint8_t>((byte << r) | (byte >> (8 - r)));
            return mba::x_xor<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 9) {  // ADD_ROL
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            uint8_t v = static_cast<uint8_t>((byte >> r) | (byte << (8 - r)));
            return mba::x_sub<uint8_t, T>(v, k);
        }
        else if constexpr (pick == 10) { // XOR_BIT
            uint8_t v = mba::x_xor<uint8_t, T>(byte, static_cast<uint8_t>((k & 0x1) ? 0xAA : 0x55));
            return mba::x_xor<uint8_t, T ^ 0x1>(v, k);
        }
        else {                           // ADD_XCHG
            uint8_t lo = static_cast<uint8_t>((byte >> 4) & 0x0F);
            uint8_t hi = static_cast<uint8_t>((byte & 0x0F) << 4);
            return mba::x_sub<uint8_t, T>(static_cast<uint8_t>(lo | hi), k);
        }
    }

    template<uint32_t Seed, size_t... I>
    KLI_FORCEINLINE void decode_bytes_seq(
        const uint8_t* chunks, uint32_t s, uint32_t key,
        const uint8_t* perm, uint8_t* bytes, meta::index_seq<I...>)
    {
        ((bytes[I] = algo_decrypt_inline<Seed, I>(chunks[perm[I]], derive_key(s, I, key))), ...);
    }

    // flowVariant 仅影响 codegen 形状 (读取顺序), 不影响最终 bytes[] 内容:
    // bytes[i] 永远是 chunks[perm[i]] 用 derive_key(s,i,key) 解出, rebuild 按固定序拼接
    template<uint32_t Seed>
    KLI_FORCEINLINE uintptr_t decode_address_inline(const uint8_t* chunks, uint32_t s, uint32_t key, const uint8_t* perm, uint32_t flowVariant, uint32_t rebuildVariant) {
        uint8_t bytes[sizeof(uintptr_t)];
        if (flowVariant == 1) {
            // 路径 B: 先全部预取 perm 后再解
            uint8_t temp[sizeof(uintptr_t)];
            for (size_t i = 0; i < sizeof(uintptr_t); ++i) temp[i] = chunks[perm[i]];
            ((bytes[0] = algo_decrypt_inline<Seed, 0>(temp[0], derive_key(s, 0, key))));
            ((bytes[1] = algo_decrypt_inline<Seed, 1>(temp[1], derive_key(s, 1, key))));
            ((bytes[2] = algo_decrypt_inline<Seed, 2>(temp[2], derive_key(s, 2, key))));
            ((bytes[3] = algo_decrypt_inline<Seed, 3>(temp[3], derive_key(s, 3, key))));
            ((bytes[4] = algo_decrypt_inline<Seed, 4>(temp[4], derive_key(s, 4, key))));
            ((bytes[5] = algo_decrypt_inline<Seed, 5>(temp[5], derive_key(s, 5, key))));
            ((bytes[6] = algo_decrypt_inline<Seed, 6>(temp[6], derive_key(s, 6, key))));
            ((bytes[7] = algo_decrypt_inline<Seed, 7>(temp[7], derive_key(s, 7, key))));
        }
        else if (flowVariant == 2) {
            // 路径 C: 逆序读取 (codegen 形状差异)
            bytes[7] = algo_decrypt_inline<Seed, 7>(chunks[perm[7]], derive_key(s, 7, key));
            bytes[6] = algo_decrypt_inline<Seed, 6>(chunks[perm[6]], derive_key(s, 6, key));
            bytes[5] = algo_decrypt_inline<Seed, 5>(chunks[perm[5]], derive_key(s, 5, key));
            bytes[4] = algo_decrypt_inline<Seed, 4>(chunks[perm[4]], derive_key(s, 4, key));
            bytes[3] = algo_decrypt_inline<Seed, 3>(chunks[perm[3]], derive_key(s, 3, key));
            bytes[2] = algo_decrypt_inline<Seed, 2>(chunks[perm[2]], derive_key(s, 2, key));
            bytes[1] = algo_decrypt_inline<Seed, 1>(chunks[perm[1]], derive_key(s, 1, key));
            bytes[0] = algo_decrypt_inline<Seed, 0>(chunks[perm[0]], derive_key(s, 0, key));
        }
        else if (flowVariant == 3) {
            // 路径 D: 交错读取
            bytes[0] = algo_decrypt_inline<Seed, 0>(chunks[perm[0]], derive_key(s, 0, key));
            bytes[7] = algo_decrypt_inline<Seed, 7>(chunks[perm[7]], derive_key(s, 7, key));
            bytes[1] = algo_decrypt_inline<Seed, 1>(chunks[perm[1]], derive_key(s, 1, key));
            bytes[6] = algo_decrypt_inline<Seed, 6>(chunks[perm[6]], derive_key(s, 6, key));
            bytes[2] = algo_decrypt_inline<Seed, 2>(chunks[perm[2]], derive_key(s, 2, key));
            bytes[5] = algo_decrypt_inline<Seed, 5>(chunks[perm[5]], derive_key(s, 5, key));
            bytes[3] = algo_decrypt_inline<Seed, 3>(chunks[perm[3]], derive_key(s, 3, key));
            bytes[4] = algo_decrypt_inline<Seed, 4>(chunks[perm[4]], derive_key(s, 4, key));
        }
        else {
            // 路径 A: 顺序
            decode_bytes_seq<Seed>(chunks, s, key, perm, bytes, meta::make_index_sequence_t<sizeof(uintptr_t)>{});
        }
        return rebuild_address(bytes, rebuildVariant);
    }

    // ── 编码端: 内联加密 (与解密端 inline_algo_pick 同分支) ──

    template<uint32_t Seed, size_t Idx>
    KLI_FORCEINLINE uint8_t algo_encrypt_inline(uint8_t byte, uint8_t k) {
        constexpr uint32_t pick = inline_algo_pick(Seed, Idx);
        if constexpr (pick == 0) {  // XOR_ROT
            uint8_t x = byte ^ k;
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            return static_cast<uint8_t>((x << r) | (x >> (8 - r)));
        }
        else if constexpr (pick == 1) {  // ADD_ROT
            uint8_t v = byte + k;
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            return static_cast<uint8_t>((v << r) | (v >> (8 - r)));
        }
        else if constexpr (pick == 2) {  // XOR_MUL
            return byte ^ static_cast<uint8_t>((k * 0x9E + 0x37) & 0xFF);
        }
        else if constexpr (pick == 3) {  // ADD_MUL
            return byte + static_cast<uint8_t>((k * 0x9E + 0x37) & 0xFF);
        }
        else if constexpr (pick == 4) {  // XOR_SWAP
            uint8_t x = byte ^ k;
            return static_cast<uint8_t>((x << 4) | (x >> 4));
        }
        else if constexpr (pick == 5) {  // ADD_NEG
            uint8_t v = byte + k;
            return static_cast<uint8_t>(~v + 1);
        }
        else if constexpr (pick == 6) {  // MUL_XOR
            uint8_t m = static_cast<uint8_t>((byte * (k | 1)) & 0xFF);
            return m ^ static_cast<uint8_t>(~k);
        }
        else if constexpr (pick == 7) {  // ROT_XOR
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            uint8_t v = static_cast<uint8_t>((byte << r) | (byte >> (8 - r)));
            return v ^ k;
        }
        else if constexpr (pick == 8) {  // XOR_ROR
            uint8_t x = byte ^ k;
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            return static_cast<uint8_t>((x >> r) | (x << (8 - r)));
        }
        else if constexpr (pick == 9) {  // ADD_ROL
            uint8_t v = byte + k;
            uint8_t r = static_cast<uint8_t>((k & 0x7) + 1);
            return static_cast<uint8_t>((v << r) | (v >> (8 - r)));
        }
        else if constexpr (pick == 10) { // XOR_BIT
            uint8_t x = byte ^ k;
            return static_cast<uint8_t>(x ^ static_cast<uint8_t>((k & 0x1) ? 0xAA : 0x55));
        }
        else {                           // ADD_XCHG
            uint8_t v  = byte + k;
            uint8_t lo = static_cast<uint8_t>((v & 0x0F) << 4);
            uint8_t hi = static_cast<uint8_t>((v >> 4) & 0x0F);
            return lo | hi;
        }
    }

    template<uint32_t Seed, size_t... I>
    KLI_FORCEINLINE void encode_bytes_seq(uintptr_t addr, uint32_t key, const uint8_t* perm, uint8_t* chunks, meta::index_seq<I...>) {
        ((chunks[perm[I]] = algo_encrypt_inline<Seed, I>(
            static_cast<uint8_t>((addr >> (I * 8)) & 0xFF),
            derive_key(Seed, I, key))), ...);
    }

    // NOTE: 算法选择已改为编译期 (inline_algo_pick), 不再依赖 raw_state
    // 编解码必须用同一公式, 否则结果不一致
    template<uint32_t Seed>
    KLI_FORCEINLINE void shared_encode_step_inline(uintptr_t addr, uint32_t raw_state, uint8_t* chunks, AlgoType* algos, uint8_t perm[8]) {
        uint32_t key = derive_main_key(Seed, raw_state);
        for (size_t i = 0; i < sizeof(uintptr_t); ++i)
            algos[i] = static_cast<AlgoType>(inline_algo_pick(Seed, i));  // 仅作记账, 解码端不读
        compute_permutation(Seed, raw_state, perm, sizeof(uintptr_t));
        encode_bytes_seq<Seed>(addr, key, perm, chunks, meta::make_index_sequence_t<sizeof(uintptr_t)>{});
    }

    // ── 混淆调用核心 ──

    template<uint32_t Seed, typename FuncPtr>
    class ObfuscatedCallImpl;

    template<uint32_t Seed, typename Ret, typename... Args>
    class ObfuscatedCallImpl<Seed, Ret(*)(Args...)> {
    private:
        using FuncType = Ret(*)(Args...);

        uint8_t  chunks_[sizeof(uintptr_t)];
        uint32_t encoded_state_;
        uint32_t flow_variant_;
        uint32_t rebuild_variant_;
        AlgoType algos_[sizeof(uintptr_t)];
        uint8_t  perm_[sizeof(uintptr_t)];

        KLI_FORCEINLINE uintptr_t decode() const {
            uint32_t raw_state = encoded_state_ ^ get_state_mask(Seed);
            uint32_t key = derive_main_key(Seed, raw_state);

            uint8_t pk = get_perm_xor_key(Seed);
            uint8_t  dec_perm[sizeof(uintptr_t)];
            for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
                dec_perm[i] = perm_[i] ^ pk;
            }

            // 内联展开: 每个调用点编译期固化用 inline_algo_pick<Seed, i> 选定的算法
            // 无全局 switch, 无 dec_algos 表; 攻击者 hook 此函数拿到的只是单个调用点的解
            uintptr_t addr = decode_address_inline<Seed>(chunks_, Seed, key, dec_perm, flow_variant_, rebuild_variant_);

            volatile uint8_t* pp = reinterpret_cast<volatile uint8_t*>(dec_perm);
            for (size_t i = 0; i < sizeof(dec_perm); ++i) pp[i] = 0;

            return addr;
        }

        static KLI_FORCEINLINE void secure_fill(void* ptr, size_t len, uint8_t fill) {
            volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
            for (size_t i = 0; i < len; ++i) p[i] = fill;
        }

    public:
        ObfuscatedCallImpl(FuncType func, uint32_t counter, uint32_t line)
            : chunks_{}
            , encoded_state_(0)
            , flow_variant_(get_flow_variant(Seed))
            , rebuild_variant_(get_rebuild_variant(Seed))
            , algos_{}
            , perm_{}
        {
            uint32_t raw_state = (counter * get_magic(Seed, 0)) ^ line;
            encoded_state_ = raw_state ^ get_state_mask(Seed);

            // 走 inline 编码: algos_[] 仅作记账 (与解码端 inline_algo_pick 一致)
            shared_encode_step_inline<Seed>(reinterpret_cast<uintptr_t>(func), raw_state, chunks_, algos_, perm_);

            uint8_t ak = get_algo_xor_key(Seed);
            uint8_t pk = get_perm_xor_key(Seed);
            for (size_t i = 0; i < sizeof(uintptr_t); ++i) {
                algos_[i] = static_cast<AlgoType>(static_cast<uint8_t>(algos_[i]) ^ ak);
                perm_[i] ^= pk;
            }
        }

        KLI_FORCEINLINE Ret operator()(Args... args) const {
            uintptr_t addr = decode();
            if (!addr) {
                if constexpr (!seed::TypeMatch<Ret, void>::value) return Ret{};
                else return;
            }
            FuncType func = reinterpret_cast<FuncType>(addr);
            if constexpr (!seed::TypeMatch<Ret, void>::value) {
                Ret r = func(args...);
                *reinterpret_cast<volatile uintptr_t*>(&addr) = 0;
                return r;
            }
            else {
                func(args...);
                *reinterpret_cast<volatile uintptr_t*>(&addr) = 0;
            }
        }

        KLI_FORCEINLINE ~ObfuscatedCallImpl() {
            uint8_t fill = static_cast<uint8_t>(seed::mix_b(Seed, 0xDD) & 0xFE | 0x01);
            secure_fill(chunks_, sizeof(chunks_), fill);
            secure_fill(&encoded_state_, sizeof(encoded_state_), fill);
            secure_fill(algos_, sizeof(algos_), fill);
            secure_fill(perm_, sizeof(perm_), fill);
        }
    };

    template<uint32_t Seed, typename Ret, typename... Args>
    KLI_FORCEINLINE auto make_obfuscated_call(Ret(*func)(Args...), uint32_t line) {
        return ObfuscatedCallImpl<Seed, Ret(*)(Args...)>(func, __COUNTER__, line);
    }

} // namespace callcrypt
} // namespace KliProtected

// =======================================================================
//  公开宏接口
// =======================================================================

// ── 返回地址欺骗 ──
#define SPOOF_FUNC \
    KliProtected::RetAddrSpoof::SpoofFunction _spf_(_AddressOfReturnAddress());

// ── 位置指纹 ──
#define KLI_LOC_FINGERPRINT  KliProtected::seed::cx_seed( \
    static_cast<uint32_t>(__COUNTER__) | (static_cast<uint32_t>(__LINE__) << 16))

// ── 编译期哈希 ──
#define KLI_HASH_A_STR_CX(str, counter) \
    (KliProtected::hash::CxForce<uint64_t, KliProtected::hash::hash_a_cx<counter>(str)>::value())

#define KLI_HASH_W_STR_CX(str, counter) \
    (KliProtected::hash::CxForce<uint32_t, KliProtected::hash::hash_w_cx<counter>(str)>::value())

// ── 字符串加密 ──
#define KLI_SCOPED_WSTR(str) \
    []() { \
        constexpr uint32_t _kli_ctr_ = KLI_LOC_FINGERPRINT; \
        constexpr KliProtected::crypt::EncryptedString<sizeof(L##str) / sizeof(wchar_t), wchar_t, _kli_ctr_> _kli_enc(L##str); \
        return KliProtected::crypt::make_decrypt<sizeof(L##str) / sizeof(wchar_t), wchar_t, _kli_ctr_>(_kli_enc); \
    }()

#define KLI_SCOPED_ASTR(str) \
    []() { \
        constexpr uint32_t _kli_ctr_ = KLI_LOC_FINGERPRINT; \
        constexpr KliProtected::crypt::EncryptedString<sizeof(str), char, _kli_ctr_> _kli_enc(str); \
        return KliProtected::crypt::make_decrypt<sizeof(str), char, _kli_ctr_>(_kli_enc); \
    }()

// ── 模块基址查找 ──
#define FindBase_IMPL(drv, name, ldr, counter) \
    KliProtected::resolve_module_base_by_hash(drv, \
        KLI_HASH_W_STR_CX(name, counter), ldr, counter)

#define FindBase(drv, name, ldr) \
    FindBase_IMPL(drv, L##name, ldr, KLI_LOC_FINGERPRINT)

// ── 导出函数地址查找 ──
#define GetFunByExport_IMPL(base, name, counter) \
    KliProtected::resolve_export_by_hash<counter>(base, \
        KLI_HASH_A_STR_CX(name, counter))

#define GetFunByExport(base, name) \
    GetFunByExport_IMPL(base, name, KLI_LOC_FINGERPRINT)

// ── 函数调用混淆 ──
#define KLI_OBFUSCATE_CALL(func) \
    KliProtected::callcrypt::make_obfuscated_call<KLI_LOC_FINGERPRINT ^ KliProtected::seed::time_seed()>(func, __LINE__)

// ── 内核导出函数查找 (noinline 共享路径, 不膨胀调用点) ──
#define KLI_FN_IMPL(kernel_base, name, counter) \
    ((decltype(&##name))(KliProtected::find_kernel_export( \
        kernel_base, KLI_HASH_A_STR_CX(#name, counter), counter)))

#define KLI_FN(kernel_base, name) \
    KLI_FN_IMPL(kernel_base, name, KLI_LOC_FINGERPRINT)

// ── MBA 公开宏 ──
// 用恒等的复杂位算术表达式替换简单运算, 阻断 IDA Hex-Rays 常量传播和模式识别
// 每个调用点用 KLI_LOC_FINGERPRINT 选取不同恒等式变体
// 宏用 Depth=2 (双层嵌套) + 外层 op_zero 不透明谓词注入; 内部热路径默认 Depth=1
// 用法: auto r = MBA_XOR(uint32_t, a, b);  等价于 a ^ b
#define MBA_XOR(T, a, b)  static_cast<T>(KliProtected::mba::x_xor<T, KLI_LOC_FINGERPRINT, 2>((T)(a), (T)(b)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0x7E>())
#define MBA_AND(T, a, b)  static_cast<T>(KliProtected::mba::x_and<T, KLI_LOC_FINGERPRINT, 2>((T)(a), (T)(b)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0x7F>())
#define MBA_OR(T, a, b)   static_cast<T>(KliProtected::mba::x_or<T, KLI_LOC_FINGERPRINT, 2>((T)(a), (T)(b)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0x90>())
#define MBA_ADD(T, a, b)  static_cast<T>(KliProtected::mba::x_add<T, KLI_LOC_FINGERPRINT, 2>((T)(a), (T)(b)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0xA0>())
#define MBA_SUB(T, a, b)  static_cast<T>(KliProtected::mba::x_sub<T, KLI_LOC_FINGERPRINT, 2>((T)(a), (T)(b)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0xB0>())
#define MBA_NOT(T, a)     static_cast<T>(KliProtected::mba::x_not<T, KLI_LOC_FINGERPRINT, 2>((T)(a)) ^ KliProtected::mba::op_zero<T, KLI_LOC_FINGERPRINT ^ 0xC0>())

// ── 常量加密 ──
// 编译期对常量做 PerMask 异或编码, 二进制中不出现明文常量
// 运行时通过 MBA_XOR 解码, 每调用点恒等式变体不同
// 用法: ULONG x = KLI_OBF_CONST(ULONG, 0x12345678);  等价于 0x12345678
#define KLI_OBF_CONST(T, val) \
    MBA_XOR(T, \
        static_cast<T>(static_cast<T>(val) ^ static_cast<T>(KliProtected::obf_const::PerMask<static_cast<uint32_t>(val) ^ 0x5A>::value)), \
        static_cast<T>(KliProtected::obf_const::PerMask<static_cast<uint32_t>(val) ^ 0x5A>::value))