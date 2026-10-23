#pragma once

// ============================================================
// kli_mba.hpp — KliProtected 第 2 层: MBA 混淆恒等式 + 编译期偏移常量
// ============================================================
// (namespace KliProtected: mba / obf_const)
// 自 KliProtected.hpp 拆出 (原样搬运); 仅由伞文件按序 include。

namespace KliProtected {
// =======================================================================
//  MBA (Mixed Boolean-Arithmetic) 混淆原语
//  用恒等的位算术表达式替换简单运算, 阻断 IDA Hex-Rays 的常量传播和模式识别
//  Depth=0: 裸操作符 (递归终止)
//  Depth=1: 单层 MBA 替换 (默认)
//  Depth=2+: 嵌套混淆
// =======================================================================

namespace mba {

    // ── 前向声明 (互相递归调用) ──
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_xor(T a, T b);
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_and(T a, T b);
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_or(T a, T b);
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_add(T a, T b);
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_sub(T a, T b);
    template<typename T, uint32_t Tag, int Depth> KLI_FORCEINLINE T x_not(T a);

    // ── 不透明谓词 (opaque predicates) ──
    // op_zero: 恒为 0 (a & ~a / a ^ a / a - a)
    // 用 volatile 变量隐藏值, IDA 无法静态证明恒等, 必须运行时执行才能消除
    template<typename T, uint32_t Tag>
    KLI_FORCEINLINE T op_zero() {
        volatile T x = static_cast<T>(seed::cx_seed(Tag) & 0xFF);
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0xAA) % 3;
        if constexpr (v == 0)      return static_cast<T>(x & static_cast<T>(~x));
        else if constexpr (v == 1) return static_cast<T>(x ^ x);
        else                       return static_cast<T>(x - x);
    }

    // ── 内部辅助: 按 Depth 决定是否递归 MBA ──
    // 这些辅助让外层 MBA 原语的子表达式可以选择性嵌套, 避免组合爆炸
    template<typename T, uint32_t Tag, int Depth>
    KLI_FORCEINLINE T mix_or(T a, T b) {
        if constexpr (Depth <= 0) return static_cast<T>(a | b);
        else                      return x_or<T, Tag, Depth - 1>(a, b);
    }
    template<typename T, uint32_t Tag, int Depth>
    KLI_FORCEINLINE T mix_and(T a, T b) {
        if constexpr (Depth <= 0) return static_cast<T>(a & b);
        else                      return x_and<T, Tag, Depth - 1>(a, b);
    }
    template<typename T, uint32_t Tag, int Depth>
    KLI_FORCEINLINE T mix_sub(T a, T b) {
        if constexpr (Depth <= 0) return static_cast<T>(a - b);
        else                      return x_sub<T, Tag, Depth - 1>(a, b);
    }
    template<typename T, uint32_t Tag, int Depth>
    KLI_FORCEINLINE T mix_add(T a, T b) {
        if constexpr (Depth <= 0) return static_cast<T>(a + b);
        else                      return x_add<T, Tag, Depth - 1>(a, b);
    }
    template<typename T, uint32_t Tag, int Depth>
    KLI_FORCEINLINE T mix_not(T a) {
        if constexpr (Depth <= 0) return static_cast<T>(~a);
        else                      return x_not<T, Tag, Depth - 1>(a);
    }

    // ── XOR 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_xor(T a, T b) {
        T va = a, vb = b;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag) & 0x3;
        if constexpr (v == 0) {
            return mix_sub<T, Tag ^ 0x60, Depth>(mix_or<T, Tag ^ 0x61, Depth>(va, vb), mix_and<T, Tag ^ 0x62, Depth>(va, vb));
        }
        else if constexpr (v == 1) {
            T andbits = mix_and<T, Tag ^ 0x63, Depth>(va, vb);
            return mix_sub<T, Tag ^ 0x64, Depth>(mix_add<T, Tag ^ 0x65, Depth>(va, vb), static_cast<T>(andbits + andbits));
        }
        else if constexpr (v == 2) {
            T andbits = mix_and<T, Tag ^ 0x66, Depth>(va, vb);
            return mix_and<T, Tag ^ 0x67, Depth>(mix_or<T, Tag ^ 0x68, Depth>(va, vb), mix_not<T, Tag ^ 0x69, Depth>(andbits));
        }
        else {
            T andbits = mix_and<T, Tag ^ 0x6A, Depth>(va, vb);
            T notaa = mix_not<T, Tag ^ 0x6B, Depth>(va);
            T notbb = mix_not<T, Tag ^ 0x6C, Depth>(vb);
            T xnorbits = mix_and<T, Tag ^ 0x6D, Depth>(notaa, notbb);
            return mix_not<T, Tag ^ 0x6E, Depth>(mix_or<T, Tag ^ 0x6F, Depth>(andbits, xnorbits));
        }
    }

    // ── AND 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_and(T a, T b) {
        T va = a, vb = b;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0x11) % 3;
        if constexpr (v == 0) {
            return mix_sub<T, Tag ^ 0x70, Depth>(mix_add<T, Tag ^ 0x71, Depth>(va, vb), mix_or<T, Tag ^ 0x72, Depth>(va, vb));
        }
        else if constexpr (v == 1) {
            return mix_sub<T, Tag ^ 0x73, Depth>(mix_or<T, Tag ^ 0x74, Depth>(va, vb), static_cast<T>(va ^ vb));
        }
        else {
            T notaa = mix_not<T, Tag ^ 0x75, Depth>(va);
            T notbb = mix_not<T, Tag ^ 0x76, Depth>(vb);
            return mix_not<T, Tag ^ 0x77, Depth>(mix_or<T, Tag ^ 0x78, Depth>(notaa, notbb));
        }
    }

    // ── OR 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_or(T a, T b) {
        T va = a, vb = b;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0x22) % 3;
        if constexpr (v == 0) {
            return mix_sub<T, Tag ^ 0x80, Depth>(mix_add<T, Tag ^ 0x81, Depth>(va, vb), mix_and<T, Tag ^ 0x82, Depth>(va, vb));
        }
        else if constexpr (v == 1) {
            return mix_add<T, Tag ^ 0x83, Depth>(mix_and<T, Tag ^ 0x84, Depth>(va, vb), static_cast<T>(va ^ vb));
        }
        else {
            T notaa = mix_not<T, Tag ^ 0x85, Depth>(va);
            T notbb = mix_not<T, Tag ^ 0x86, Depth>(vb);
            return mix_not<T, Tag ^ 0x87, Depth>(mix_and<T, Tag ^ 0x88, Depth>(notaa, notbb));
        }
    }

    // ── ADD 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_add(T a, T b) {
        T va = a, vb = b;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0x33) % 3;
        if constexpr (v == 0) {
            T andbits = mix_and<T, Tag ^ 0x91, Depth>(va, vb);
            return mix_add<T, Tag ^ 0x92, Depth>(static_cast<T>(va ^ vb), static_cast<T>(andbits + andbits));
        }
        else if constexpr (v == 1) {
            return mix_add<T, Tag ^ 0x93, Depth>(mix_or<T, Tag ^ 0x94, Depth>(va, vb), mix_and<T, Tag ^ 0x95, Depth>(va, vb));
        }
        else {
            T notvb = mix_not<T, Tag ^ 0x96, Depth>(vb);
            return mix_sub<T, Tag ^ 0x97, Depth>(mix_sub<T, Tag ^ 0x98, Depth>(va, notvb), static_cast<T>(1));
        }
    }

    // ── SUB 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_sub(T a, T b) {
        T va = a, vb = b;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0x44) % 3;
        if constexpr (v == 0) {
            T notvb = mix_not<T, Tag ^ 0xA1, Depth>(vb);
            return mix_add<T, Tag ^ 0xA2, Depth>(mix_add<T, Tag ^ 0xA3, Depth>(va, notvb), static_cast<T>(1));
        }
        else if constexpr (v == 1) {
            T nb = static_cast<T>(-vb);
            T andnb = mix_and<T, Tag ^ 0xA4, Depth>(va, nb);
            return mix_add<T, Tag ^ 0xA5, Depth>(static_cast<T>(va ^ nb), static_cast<T>(andnb + andnb));
        }
        else {
            T diff = mix_sub<T, Tag ^ 0xA6, Depth>(vb, va);
            return static_cast<T>(-diff);
        }
    }

    // ── NOT 恒等式集 ──
    template<typename T, uint32_t Tag, int Depth = 1>
    KLI_FORCEINLINE T x_not(T a) {
        T va = a;
        _ReadWriteBarrier();
        constexpr uint32_t v = seed::cx_seed(Tag ^ 0x55) % 3;
        if constexpr (v == 0) {
            return mix_sub<T, Tag ^ 0xB1, Depth>(static_cast<T>(-va), static_cast<T>(1));
        }
        else if constexpr (v == 1) {
            return static_cast<T>(va ^ static_cast<T>(~static_cast<T>(0)));
        }
        else {
            T inc = mix_add<T, Tag ^ 0xB3, Depth>(va, static_cast<T>(1));
            return static_cast<T>(static_cast<T>(0) - inc);
        }
    }

} // namespace mba

// =======================================================================
//  常量混淆 (消除硬编码立即数特征)
// =======================================================================

namespace obf_const {

    // 每常量独立掩码, 二进制中无可聚类的共享 mask
    template<uint32_t Tag>
    struct PerMask {
        static constexpr uint32_t value = seed::mix(seed::time_seed(), 0xCA ^ Tag);
    };

    // ── 值常量编码 ──

    constexpr uint16_t DOS_SIG_E = 0x5A4D ^ static_cast<uint16_t>(PerMask<0x5A4D>::value);
    constexpr uint32_t PE_SIG_E = 0x4550 ^ PerMask<0x4550>::value;
    constexpr uint32_t KTHREAD_OFF_E = 0x188 ^ PerMask<0x188>::value;
    constexpr uint32_t KSTACK_BASE_E = 0x030 ^ PerMask<0x030>::value;
    constexpr uint32_t KSTACK_LIMIT_E = 0x038 ^ PerMask<0x038>::value;

    // noinline 解码: 用 MBA 替换 XOR, 阻止跨函数常量折叠
    KLI_NOINLINE uint16_t dos_sig() { return mba::x_xor<uint16_t, 0x5A4D>(DOS_SIG_E, static_cast<uint16_t>(PerMask<0x5A4D>::value)); }
    KLI_NOINLINE uint32_t pe_sig() { return mba::x_xor<uint32_t, 0x4550>(PE_SIG_E, PerMask<0x4550>::value); }
    KLI_NOINLINE uint32_t kthread_off() { return mba::x_xor<uint32_t, 0x188>(KTHREAD_OFF_E, PerMask<0x188>::value); }
    KLI_NOINLINE uint32_t kstack_base() { return mba::x_xor<uint32_t, 0x030>(KSTACK_BASE_E, PerMask<0x030>::value); }
    KLI_NOINLINE uint32_t kstack_limit() { return mba::x_xor<uint32_t, 0x038>(KSTACK_LIMIT_E, PerMask<0x038>::value); }

    // ── PE 偏移编码 (每偏移独立掩码) ──

    constexpr uint32_t OFF_DOS_MAGIC_E = 0x00 ^ PerMask<0x0100>::value;  // Tag 加偏移避免与值常量碰撞
    constexpr uint32_t OFF_DOS_LFANEW_E = 0x3C ^ PerMask<0x013C>::value;
    constexpr uint32_t OFF_PE_SIG_E = 0x00 ^ PerMask<0x0200>::value;
    constexpr uint32_t OFF_FH_NUMSECTIONS_E = 0x02 ^ PerMask<0x0202>::value;
    constexpr uint32_t OFF_FH_SIZEOFOPTHEADER_E = 0x10 ^ PerMask<0x0210>::value;
    constexpr uint32_t OFF_OH_DATADIR_E = 0x70 ^ PerMask<0x0270>::value;
    constexpr uint32_t SIZEOF_DATADIR_ENTRY_E = 8 ^ PerMask<0x0308>::value;
    constexpr uint32_t OFF_EXP_NUMNAMES_E = 0x18 ^ PerMask<0x0418>::value;
    constexpr uint32_t OFF_EXP_ADDROFFUNCTIONS_E = 0x1C ^ PerMask<0x041C>::value;
    constexpr uint32_t OFF_EXP_ADDROFNAMES_E = 0x20 ^ PerMask<0x0420>::value;
    constexpr uint32_t OFF_EXP_ADDROFNAMEORDINALS_E = 0x24 ^ PerMask<0x0424>::value;
    constexpr uint32_t DIR_EXPORT_E = 0 ^ PerMask<0x0500>::value;

    // 批量解码结构, 单次 noinline 调用解码所有偏移
    struct PeOff {
        uint32_t dos_magic;
        uint32_t dos_lfanew;
        uint32_t pe_sig;
        uint32_t fh_numsections;
        uint32_t fh_sizeofoftheader;
        uint32_t oh_datadir;
        uint32_t sizeof_datadir_entry;
        uint32_t exp_numnames;
        uint32_t exp_addroffunctions;
        uint32_t exp_addrofnames;
        uint32_t exp_addrofnameordinals;
        uint32_t dir_export;
    };

    KLI_NOINLINE PeOff pe_off() {
        return {
            mba::x_xor<uint32_t, 0x0100>(OFF_DOS_MAGIC_E,              PerMask<0x0100>::value),
            mba::x_xor<uint32_t, 0x013C>(OFF_DOS_LFANEW_E,             PerMask<0x013C>::value),
            mba::x_xor<uint32_t, 0x0200>(OFF_PE_SIG_E,                 PerMask<0x0200>::value),
            mba::x_xor<uint32_t, 0x0202>(OFF_FH_NUMSECTIONS_E,         PerMask<0x0202>::value),
            mba::x_xor<uint32_t, 0x0210>(OFF_FH_SIZEOFOPTHEADER_E,     PerMask<0x0210>::value),
            mba::x_xor<uint32_t, 0x0270>(OFF_OH_DATADIR_E,             PerMask<0x0270>::value),
            mba::x_xor<uint32_t, 0x0308>(SIZEOF_DATADIR_ENTRY_E,       PerMask<0x0308>::value),
            mba::x_xor<uint32_t, 0x0418>(OFF_EXP_NUMNAMES_E,           PerMask<0x0418>::value),
            mba::x_xor<uint32_t, 0x041C>(OFF_EXP_ADDROFFUNCTIONS_E,    PerMask<0x041C>::value),
            mba::x_xor<uint32_t, 0x0420>(OFF_EXP_ADDROFNAMES_E,        PerMask<0x0420>::value),
            mba::x_xor<uint32_t, 0x0424>(OFF_EXP_ADDROFNAMEORDINALS_E, PerMask<0x0424>::value),
            mba::x_xor<uint32_t, 0x0500>(DIR_EXPORT_E,                 PerMask<0x0500>::value)
        };
    }

    // ── RET 操作码编码 (每条独立掩码) ──

    constexpr uint32_t RET_OPCODE_E = 0xC3 ^ PerMask<0x06C3>::value;
    constexpr uint32_t POP_RET_LO_E = 0x58 ^ PerMask<0x0658>::value;   // pop rax
    constexpr uint32_t POP_RET_HI_E = 0x5F ^ PerMask<0x065F>::value;   // pop rdi
    constexpr uint32_t LEAVE_OP_E = 0xC9 ^ PerMask<0x06C9>::value;     // leave
    constexpr uint32_t NOP_OP_E = 0x90 ^ PerMask<0x0690>::value;       // nop
    constexpr uint32_t INT3_OP_E = 0xCC ^ PerMask<0x06CC>::value;      // int 3

    KLI_NOINLINE uint8_t ret_opcode() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x06C3>(RET_OPCODE_E, PerMask<0x06C3>::value)); return _v; }
    KLI_NOINLINE uint8_t pop_ret_lo() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x0658>(POP_RET_LO_E, PerMask<0x0658>::value)); return _v; }
    KLI_NOINLINE uint8_t pop_ret_hi() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x065F>(POP_RET_HI_E, PerMask<0x065F>::value)); return _v; }
    KLI_NOINLINE uint8_t leave_opcode() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x06C9>(LEAVE_OP_E, PerMask<0x06C9>::value)); return _v; }
    KLI_NOINLINE uint8_t nop_opcode() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x0690>(NOP_OP_E, PerMask<0x0690>::value)); return _v; }
    KLI_NOINLINE uint8_t int3_opcode() { volatile uint8_t _v = static_cast<uint8_t>(mba::x_xor<uint32_t, 0x06CC>(INT3_OP_E, PerMask<0x06CC>::value)); return _v; }

} // namespace obf_const
} // namespace KliProtected