// =====================================================================
// 极简 x64 长度反汇编 (LDE) + RIP 相对指令字段提取
// ─────────────────────────────────────────────────────────────────────
// · 无数据表 (规避 HDE/Capstone 等已知反汇编器的特征表签名)
// · 仅暴露 ScatteredMapper 需要的字段
// · 不处理 0F 38 / 0F 3A 三字节 opcode (C++ 内核驱动产物里无 SSE4/AVX/VEX/EVEX)
// =====================================================================
#ifndef _LDE_HPP_
#define _LDE_HPP_

namespace lde {

    // =================================================================
    //  类型别名
    // =================================================================

    typedef INT8   i8;
    typedef INT16  i16;
    typedef INT32  i32;
    typedef INT64  i64;
    typedef UINT8  u8;
    typedef UINT16 u16;
    typedef UINT32 u32;
    typedef UINT64 u64;

    // =================================================================
    //  对外字段集 — Insn
    // =================================================================

    struct Insn {
        u8  len;            // 总字节数, 0 = 解码失败
        u8  opcode;         // 主 opcode (0F 前缀时仍是 0x0F)
        u8  opcode2;        // 0F xx 中的 xx, 否则 0
        u8  modrm_reg;      // ModR/M reg (0..7)
        u8  modrm_mod;      // 0..3
        u8  modrm_rm;       // 0..7
        u8  rex_r;          // REX.R (0/1)
        u8  has_rip_rel;    // 1 = RIP 相对指令 (LEA/CALL/JMP/Jcc)
        i64 rel_distance;   // RIP 相对偏移 (LEA disp32 / CALL/JMP/Jcc imm)
    };

    // =================================================================
    //  指令属性 — OpInfo
    // =================================================================

    struct OpInfo {
        u8 has_modrm = 0;
        u8 imm_size  = 0;   // 固定 imm 大小 (0/1/2/3/4/8)
        u8 imm_osz   = 0;   // imm 跟随操作数宽度 (66H → 2, REX.W 例外 → 8)
        u8 is_rel    = 0;   // imm 是 RIP 相对偏移
        u8 invalid   = 0;   // 此 opcode 在 x64 mutator 输出里不会出现
    };

    // =================================================================
    //  内存读取 (调用方保证 buf 后至少 16 字节连续)
    // =================================================================

    static __forceinline u8  _r8 (const u8* p) { return *p; }
    static __forceinline u16 _r16(const u8* p) { return *(const u16*)p; }
    static __forceinline u32 _r32(const u8* p) { return *(const u32*)p; }
    static __forceinline u64 _r64(const u8* p) { return *(const u64*)p; }

    // =================================================================
    //  ModR/M 解码 (+SIB +disp), 兼 LEA[rip+] RIP-rel 抽取
    //  返回 0 = 无效; 同时写回 modrm_*; 对 LEA[rip+] 顺手填 has_rip_rel/rel_distance
    // =================================================================

    static __forceinline u32 _DecodeModRM(const u8* p, u32 max, u8 asz67, Insn* out, u8 main_opcode) {
        if (max < 1) return 0;
        u8 modrm = p[0];
        u8 mod = (u8)(modrm >> 6);
        u8 reg = (u8)((modrm >> 3) & 7);
        u8 rm  = (u8)(modrm & 7);
        out->modrm_mod = mod;
        out->modrm_reg = reg;
        out->modrm_rm  = rm;

        u32 used = 1;
        if (mod == 3) return used;                              // 纯寄存器寻址

        // mod=0 rm=5: 64-bit 下是 RIP+disp32; 32-bit (asz67) 下是 [disp32]
        if (mod == 0 && rm == 5) {
            if (max < used + 4) return 0;
            if (!asz67 && main_opcode == 0x8D) {                // LEA [rip+disp32]
                out->has_rip_rel  = 1;
                out->rel_distance = (i32)_r32(p + used);
            }
            return used + 4;
        }

        // SIB
        if (rm == 4) {
            if (max < used + 1) return 0;
            u8 sib = p[used++];
            if (mod == 0 && (sib & 7) == 5) {                   // SIB base=5 + mod=0 → disp32
                if (max < used + 4) return 0;
                return used + 4;
            }
        }

        // 普通 disp (mod=1 → disp8, mod=2 → disp32)
        if (mod == 1) { 
            if (max < used + 1) return 0; used += 1;
        }
        else if (mod == 2) { 
            if (max < used + 4) return 0; used += 4;
        }
        return used;
    }

    // =================================================================
    //  1 字节 opcode 分类
    // =================================================================

    static __forceinline OpInfo _Classify1B(u8 op) {
        OpInfo r;

        // 00-3F: ALU 一字节族 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP), 低 3 位决定形式
        if (op <= 0x3F) {
            u8 lo = (u8)(op & 7);
            if (lo <= 3) { r.has_modrm = 1; return r; }         // xx0..xx3: ModR/M
            if (lo == 4) { r.imm_size  = 1; return r; }         // xx4: AL, imm8
            if (lo == 5) { r.imm_osz   = 1; return r; }         // xx5: EAX, imm16/32
            r.invalid = 1; return r;                            // xx6/xx7: x64 段相关/BCD 无效
        }
        if (op <= 0x4F) { r.invalid = 1; return r; }            // 40-4F: REX (已消化)
        if (op <= 0x5F) return r;                               // 50-5F: PUSH/POP r64
        if (op <= 0x62) { r.invalid = 1; return r; }            // 60-62: PUSHA/POPA/ARPL x64 无效
        if (op == 0x63) { r.has_modrm = 1; return r; }          // MOVSXD r64, r/m32

        // 66/67/64/65/F0/F2/F3 = 前缀 (已消化), EA = far jmp ptr16:32 x64 无效
        // C4/C5 = VEX/LES/LDS (mutator 不产出), D4/D5/D6 = AAM/AAD x64 无效
        if (op == 0x66 || op == 0x67 || op == 0x64 || op == 0x65 ||
            op == 0xF0 || op == 0xF2 || op == 0xF3 ||
            op == 0xEA ||
            op == 0xC4 || op == 0xC5 ||
            op == 0xD4 || op == 0xD5 || op == 0xD6)
        {
            r.invalid = 1; return r;
        }

        // 68 PUSH imm32, 69 IMUL imm32, 6A PUSH imm8, 6B IMUL imm8
        if (op == 0x68) { r.imm_osz  = 1; return r; }
        if (op == 0x69) { r.has_modrm = 1; r.imm_osz  = 1; return r; }
        if (op == 0x6A) { r.imm_size  = 1; return r; }
        if (op == 0x6B) { r.has_modrm = 1; r.imm_size = 1; return r; }
        if (op <= 0x6F) return r;                               // 6C-6F: INS/OUTS

        // 70-7F: Jcc short rel8
        if (op <= 0x7F) { r.imm_size = 1; r.is_rel = 1; return r; }

        // 80-83: 组指令 (ALU r/m, imm)
        if (op == 0x80 || op == 0x82 || op == 0x83) { r.has_modrm = 1; r.imm_size = 1; return r; }
        if (op == 0x81) { r.has_modrm = 1; r.imm_osz = 1; return r; }
        if (op <= 0x8F) { r.has_modrm = 1; return r; }          // 84-8F: TEST/MOV/LEA/NOP 等
        if (op <= 0x9F) return r;                               // 90-9F: XCHG/CBW/CWD/...

        // A0-A3: MOV AL/AX/RAX, moffs (64-bit moffs)
        if (op <= 0xA3) { r.imm_size = 8; return r; }
        if (op <= 0xA7) return r;                               // A4-A7: MOVS/CMPS
        if (op == 0xA8) { r.imm_size = 1; return r; }           // TEST AL, imm8
        if (op == 0xA9) { r.imm_osz  = 1; return r; }           // TEST EAX, imm
        if (op <= 0xAF) return r;                               // AA-AF: STOS/LODS/SCAS

        // B0-B7: MOV r8, imm8;  B8-BF: MOV r16/32/64, imm (REX.W → imm64)
        if (op <= 0xB7) { r.imm_size = 1; return r; }
        if (op <= 0xBF) { r.imm_osz  = 1; return r; }

        // C0-CF: 移位组 / RET / MOV imm / ENTER / LEAVE / INT3 等
        if (op == 0xC0 || op == 0xC1) { r.has_modrm = 1; r.imm_size = 1; return r; }
        if (op == 0xC2) { r.imm_size = 2; return r; }           // RET imm16
        if (op == 0xC3) return r;                               // RET
        if (op == 0xC6) { r.has_modrm = 1; r.imm_size = 1; return r; }
        if (op == 0xC7) { r.has_modrm = 1; r.imm_osz  = 1; return r; }
        if (op == 0xC8) { r.imm_size = 3; return r; }           // ENTER imm16, imm8
        if (op == 0xC9) return r;                               // LEAVE
        if (op == 0xCA) { r.imm_size = 2; return r; }           // RETF imm16
        if (op == 0xCB || op == 0xCC || op == 0xCE || op == 0xCF) return r;  // RETF/INT3/INTO/IRET
        if (op == 0xCD) { r.imm_size = 1; return r; }           // INT imm8

        // D0-D3 移位组, D7 XLAT, D8-DF FPU
        if (op <= 0xD3) { r.has_modrm = 1; return r; }
        if (op == 0xD7) return r;
        if (op <= 0xDF) { r.has_modrm = 1; return r; }

        // E0-E3: LOOPcc/JCXZ rel8
        if (op <= 0xE3) { r.imm_size = 1; r.is_rel = 1; return r; }
        // E4-E7: IN/OUT imm8
        if (op <= 0xE7) { r.imm_size = 1; return r; }
        // E8: CALL rel32, E9: JMP rel32, EB: JMP rel8
        if (op == 0xE8 || op == 0xE9) { r.imm_size = 4; r.is_rel = 1; return r; }
        if (op == 0xEB) { r.imm_size = 1; r.is_rel = 1; return r; }
        // EC-EF: IN/OUT DX; F4/F5: HLT/CMC; F8-FD: CLC/STC/CLI/STI/CLD/STD
        if (op <= 0xEF) return r;
        if (op == 0xF4 || op == 0xF5) return r;
        // F6/F7: 组指令 (TEST imm 形式 reg=0/1, 外层根据 modrm.reg 修正 imm)
        if (op == 0xF6 || op == 0xF7) { r.has_modrm = 1; return r; }
        if (op <= 0xFD) return r;
        // FE/FF: 组指令 (INC/DEC/CALL/JMP/PUSH r/m)
        if (op == 0xFE || op == 0xFF) { r.has_modrm = 1; return r; }

        r.invalid = 1; return r;
    }

    // =================================================================
    //  2 字节 opcode 分类 (0F xx)
    //  只需正确算长度; ScatteredMapper 真正关心的只有 Jcc long (0F 80..8F)
    // =================================================================

    static __forceinline OpInfo _Classify2B(u8 op2) {
        OpInfo r;

        // 80-8F: Jcc long rel32 (ScatteredMapper 重写目标)
        if (op2 >= 0x80 && op2 <= 0x8F) { r.imm_size = 4; r.is_rel = 1; return r; }

        // 38/3A: 三字节 opcode 头 (SSE4/AES/PCLMUL), mutator 不产出
        if (op2 == 0x38 || op2 == 0x3A) { r.invalid = 1; return r; }

        // 带 ModR/M 的大段范围: 00-03 (LLDT/SGDT), 10-1F (SSE MOV), 20-23 (MOV cr/dr),
        // 40-4F (CMOVcc), 50-7F (SSE), 90-9F (SETcc), B0-B1 (CMPXCHG), B2-B7 (LSS/MOVZX),
        // BB-BF (BTC/BSF/BSR/MOVSX), C0-C7 (XADD/MOVNTI), D0-FF (SSE/MMX)
        if (op2 <= 0x03) { r.has_modrm = 1; return r; }
        if (op2 >= 0x10 && op2 <= 0x23) { r.has_modrm = 1; return r; }
        if (op2 >= 0x40 && op2 <= 0x7F) { r.has_modrm = 1; return r; }
        if (op2 >= 0x90 && op2 <= 0x9F) { r.has_modrm = 1; return r; }
        if (op2 == 0xA3 || op2 == 0xA5) { r.has_modrm = 1; return r; }
        if (op2 == 0xA4) { r.has_modrm = 1; r.imm_size = 1; return r; }    // SHLD imm8
        if (op2 >= 0xAB && op2 <= 0xAF) {
            if (op2 == 0xAC) { r.has_modrm = 1; r.imm_size = 1; return r; }  // SHRD imm8
            r.has_modrm = 1; return r;
        }
        if (op2 >= 0xB0 && op2 <= 0xB9) { r.has_modrm = 1; return r; }
        if (op2 == 0xBA) { r.has_modrm = 1; r.imm_size = 1; return r; }    // BT/BTS/BTR/BTC imm8
        if (op2 >= 0xBB && op2 <= 0xBF) { r.has_modrm = 1; return r; }
        if (op2 == 0xC2 || op2 == 0xC4 || op2 == 0xC5 || op2 == 0xC6) {
            r.has_modrm = 1; r.imm_size = 1; return r;
        }
        if (op2 >= 0xC0 && op2 <= 0xC7) { r.has_modrm = 1; return r; }
        if (op2 >= 0xD0) { r.has_modrm = 1; return r; }

        // 无 ModR/M 无 imm: 系统指令 (RDTSC/CPUID/SYSCALL/...), PUSH/POP seg, BSWAP
        // 05/07/09/0B/0E (SYSCALL/CLTS/WBINVD/UD2/FEMMS), 30-37 (WRMSR/RDTSC/...),
        // A0/A1/A2/A8/A9 (PUSH/POP FS/GS, CPUID), C8-CF (BSWAP)
        if (op2 == 0x05 || op2 == 0x07 || op2 == 0x09 || op2 == 0x0B || op2 == 0x0E) return r;
        if (op2 >= 0x30 && op2 <= 0x37) return r;
        if (op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA2 || op2 == 0xA8 || op2 == 0xA9) return r;
        if (op2 >= 0xC8 && op2 <= 0xCF) return r;

        r.invalid = 1; return r;
    }

    // =================================================================
    //  主解码入口 — Decode
    //  解析 [buf, buf+max) 一条指令; buf 后必须至少 16 字节可读
    //  返回字节数 (=out->len), 0 = 解码失败
    // =================================================================

    static __forceinline u32 Decode(const u8* buf, u32 max, Insn* out) {
        __stosb((u8*)out, 0, sizeof(Insn));
        if (!buf || !max) return 0;

        const u8* p = buf;
        u32 left = max;

        // ── 步骤 1: legacy 前缀 + REX (REX 必须紧接 opcode) ──
        u8 osz66 = 0, asz67 = 0, rex = 0;
        for (u32 i = 0; i < 14; i++) {
            if (!left) return 0;
            u8 c = *p;
            if (c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x26 || c == 0x2E || c == 0x36 || c == 0x3E || c == 0x64 || c == 0x65) { p++; left--; continue; }
            if (c == 0x66) { osz66 = 1; p++; left--; continue; }
            if (c == 0x67) { asz67 = 1; p++; left--; continue; }
            if ((c & 0xF0) == 0x40) { rex = c; p++; left--; break; }
            break;
        }
        out->rex_r = (u8)((rex >> 2) & 1);
        u8 rex_w = (u8)((rex >> 3) & 1);

        // ── 步骤 2: opcode (0F xx 是 2 字节) ──
        if (!left) return 0;
        u8 op = *p++; left--;
        out->opcode = op;

        OpInfo info;
        if (op == 0x0F) {
            if (!left) return 0;
            u8 op2 = *p++; left--;
            out->opcode2 = op2;
            info = KLI_OBFUSCATE_CALL(_Classify2B)(op2);
        }
        else {
            info = KLI_OBFUSCATE_CALL(_Classify1B)(op);
        }
        if (info.invalid) return 0;

        // ── 步骤 3: ModR/M (+SIB +disp) ──
        if (info.has_modrm) {
            u32 used = KLI_OBFUSCATE_CALL(_DecodeModRM)(p, left, asz67, out, op);
            if (!used) return 0;
            // F6/F7 组 reg=0/1 形态带 imm
            if (op == 0xF6 && out->modrm_reg <= 1) info.imm_size = 1;
            if (op == 0xF7 && out->modrm_reg <= 1) info.imm_osz  = 1;
            p += used; left -= used;
        }

        // ── 步骤 4: imm / rel ──
        u8 imm_len = info.imm_size;
        if (info.imm_osz) {
            // 默认 osz=32 → imm 4B; 66H → 2B; B8-BF + REX.W 例外 → imm 8B
            if ((op >= 0xB8 && op <= 0xBF) && rex_w) imm_len = 8;
            else if (osz66) imm_len = 2;
            else imm_len = 4;
        }
        if (left < imm_len) return 0;

        if (info.is_rel) {
            out->has_rip_rel = 1;
            switch (imm_len) {
            case 1: out->rel_distance = (i8)_r8(p); break;
            case 2: out->rel_distance = (i16)_r16(p); break;
            case 4: out->rel_distance = (i32)_r32(p); break;
            case 8: out->rel_distance = (i64)_r64(p); break;
            }
        }
        p += imm_len; left -= imm_len;

        u32 total = (u32)(p - buf);
        if (total > 15) return 0;                               // x86 单指令上限
        out->len = (u8)total;
        return total;
    }

    // =================================================================
    //  重写目标判定 — IsRewriteTarget
    //  仅筛 ScatteredMapper 需要重写的 RIP 相对指令: LEA[rip+]/CALL/JMP/Jcc
    //  ret / 间接 call / 间接 jmp 走"原字节复制"分支, 这里不返回 true
    // =================================================================

    static __forceinline bool IsRewriteTarget(const Insn& in) {
        u8 op = in.opcode;
        if (op == 0x8D && in.modrm_mod == 0 && in.modrm_rm == 5) return true;    // LEA [rip+]
        if (op == 0xE8 || op == 0xE9 || op == 0xEB) return true;                 // CALL/JMP rel
        if (op >= 0x70 && op <= 0x7F) return true;                               // Jcc short
        if (op == 0x0F && in.opcode2 >= 0x80 && in.opcode2 <= 0x8F) return true; // Jcc long
        return false;
    }

} // namespace lde

#endif