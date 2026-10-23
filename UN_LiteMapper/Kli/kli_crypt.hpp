#pragma once

// ============================================================
// kli_crypt.hpp — KliProtected 第 4 层: 编译期字符串/数据加解密
// ============================================================
// (namespace KliProtected: crypt)
// 自 KliProtected.hpp 拆出 (原样搬运); 仅由伞文件按序 include。

namespace KliProtected {
// =======================================================================
//  字符串加密与解密 (ARX 流密码 + 密钥分片)
// =======================================================================

namespace crypt {

    KLI_FORCEINLINE constexpr uint32_t arx_derive_stream(uint32_t base_key, size_t i) {
        uint32_t k = base_key ^ static_cast<uint32_t>(i);
        k = (k << 13) | (k >> 19);
        k ^= k >> 17;
        return k;
    }

    // 4 轮不可逆密钥推导
    constexpr uint32_t derive_key_irreversible(uint32_t base, uint32_t salt) {
        uint32_t k = seed::mix(base, 0xE1 ^ salt);
        k = seed::mix_b(k, salt);
        k = seed::mix(k, ~salt);
        k = seed::mix_b(k, salt ^ seed::IRREVERSIBLE_SALT);
        return k;
    }

    // 密文哈希: 绑定密钥分片到密文内容 (运行时调用, 用 MBA 混淆 codegen)
    template<size_t N, typename Char, uint32_t Tag = 0>
    KLI_FORCEINLINE uint32_t ciphertext_hash(const Char(&data)[N]) {
        uint32_t h = seed::FNV1A_OFFSET32;
        for (size_t i = 0; i < N; ++i) {
            h = mba::x_xor<uint32_t, Tag ^ 0xF1>(h, static_cast<uint32_t>(static_cast<uint8_t>(data[i] & 0xFF)));
            h *= seed::FNV1A_PRIME32;
            h = mba::x_xor<uint32_t, Tag ^ 0xF2>(h, static_cast<uint32_t>(static_cast<uint8_t>((data[i] >> 8) & 0xFF)));
            h *= seed::FNV1A_PRIME32;
        }
        return h;
    }

    // ── ARX 变体: 4 种数学互逆形式, 按 (Counter % 4) 编译期分叉 ──
    // 每个调用点的 ARX 加密/解密 codegen 形状完全不同, 攻击者识别一种
    // 形态不能套用到其它密文位置
    template<uint32_t Counter>
    KLI_FORCEINLINE constexpr uint32_t arx_variant_pick() {
        return seed::cx_seed(Counter) & 0x3;  // 0..3
    }

    // ── 单字节 (uint8_t) 加解密 ──

    // 加密: 单字节
    template<uint32_t Counter>
    KLI_FORCEINLINE constexpr uint8_t arx_enc_u8(uint8_t x, uint8_t k) {
        constexpr uint32_t v = arx_variant_pick<Counter>();
        if constexpr (v == 0) {        // V0: (x+k) <<<3 ^ (k>>2)
            x = static_cast<uint8_t>(x + k);
            x = static_cast<uint8_t>((x << 3) | (x >> 5));
            return x ^ static_cast<uint8_t>(k >> 2);
        }
        else if constexpr (v == 1) {   // V1: (x^k) <<<5 + (k|1)
            x = static_cast<uint8_t>(x ^ k);
            x = static_cast<uint8_t>((x << 5) | (x >> 3));
            return static_cast<uint8_t>(x + static_cast<uint8_t>(k | 1));
        }
        else if constexpr (v == 2) {   // V2: ~(x-k) ^ (k<<1)
            x = static_cast<uint8_t>(~(x - k));
            return x ^ static_cast<uint8_t>(k << 1);
        }
        else {                         // V3: (x+k) <<<7 ^ k ^ (k>>4)
            x = static_cast<uint8_t>(x + k);
            x = static_cast<uint8_t>((x << 7) | (x >> 1));
            return x ^ k ^ static_cast<uint8_t>(k >> 4);
        }
    }

    // 解密: 单字节 (与 enc 严格互逆)
    // 解密路径不是 constexpr (MBA 需要运行时), arx_enc 仍 constexpr 用于编译期加密
    // 热路径用 Depth=1 (字符串每字符调一次)
    template<uint32_t Counter>
    KLI_FORCEINLINE uint8_t arx_dec_u8(uint8_t x, uint8_t k) {
        constexpr uint32_t v = arx_variant_pick<Counter>();
        if constexpr (v == 0) {        // V0 逆
            x = mba::x_xor<uint8_t, Counter ^ 0xD0, 1>(x, static_cast<uint8_t>(k >> 2));
            x = static_cast<uint8_t>((x >> 3) | (x << 5));
            return mba::x_sub<uint8_t, Counter ^ 0xD1, 1>(x, k);
        }
        else if constexpr (v == 1) {   // V1 逆
            x = mba::x_sub<uint8_t, Counter ^ 0xD2, 1>(x, static_cast<uint8_t>(k | 1));
            x = static_cast<uint8_t>((x >> 5) | (x << 3));
            return mba::x_xor<uint8_t, Counter ^ 0xD3, 1>(x, k);
        }
        else if constexpr (v == 2) {   // V2 逆: ^(k<<1) ~ +k
            x = mba::x_xor<uint8_t, Counter ^ 0xD4, 1>(x, static_cast<uint8_t>(k << 1));
            x = mba::x_not<uint8_t, Counter ^ 0xD5, 1>(x);
            return mba::x_add<uint8_t, Counter ^ 0xD6, 1>(x, k);
        }
        else {                         // V3 逆
            x = mba::x_xor<uint8_t, Counter ^ 0xD7, 1>(x, static_cast<uint8_t>(k ^ static_cast<uint8_t>(k >> 4)));
            x = static_cast<uint8_t>((x >> 7) | (x << 1));
            return mba::x_sub<uint8_t, Counter ^ 0xD8, 1>(x, k);
        }
    }

    // ── 双字节 (wchar_t) 加解密 ──

    // 加密: 双字节
    template<uint32_t Counter>
    KLI_FORCEINLINE constexpr uint16_t arx_enc_u16(uint16_t x, uint16_t k) {
        constexpr uint32_t v = arx_variant_pick<Counter>();
        if constexpr (v == 0) {        // V0: (x+k) <<<5 ^ (k>>3)
            x = static_cast<uint16_t>(x + k);
            x = static_cast<uint16_t>((x << 5) | (x >> 11));
            return x ^ static_cast<uint16_t>(k >> 3);
        }
        else if constexpr (v == 1) {   // V1: (x^k) <<<9 + (k|1)
            x = static_cast<uint16_t>(x ^ k);
            x = static_cast<uint16_t>((x << 9) | (x >> 7));
            return static_cast<uint16_t>(x + static_cast<uint16_t>(k | 1));
        }
        else if constexpr (v == 2) {   // V2: ~(x-k) ^ (k<<2)
            x = static_cast<uint16_t>(~(x - k));
            return x ^ static_cast<uint16_t>(k << 2);
        }
        else {                         // V3: (x+k) <<<13 ^ k ^ (k>>5)
            x = static_cast<uint16_t>(x + k);
            x = static_cast<uint16_t>((x << 13) | (x >> 3));
            return x ^ k ^ static_cast<uint16_t>(k >> 5);
        }
    }

    // 解密: 双字节 (与 enc 严格互逆, 热路径 Depth=1)
    template<uint32_t Counter>
    KLI_FORCEINLINE uint16_t arx_dec_u16(uint16_t x, uint16_t k) {
        constexpr uint32_t v = arx_variant_pick<Counter>();
        if constexpr (v == 0) {        // V0 逆
            x = mba::x_xor<uint16_t, Counter ^ 0xE0, 1>(x, static_cast<uint16_t>(k >> 3));
            x = static_cast<uint16_t>((x >> 5) | (x << 11));
            return mba::x_sub<uint16_t, Counter ^ 0xE1, 1>(x, k);
        }
        else if constexpr (v == 1) {   // V1 逆
            x = mba::x_sub<uint16_t, Counter ^ 0xE2, 1>(x, static_cast<uint16_t>(k | 1));
            x = static_cast<uint16_t>((x >> 9) | (x << 7));
            return mba::x_xor<uint16_t, Counter ^ 0xE3, 1>(x, k);
        }
        else if constexpr (v == 2) {   // V2 逆
            x = mba::x_xor<uint16_t, Counter ^ 0xE4, 1>(x, static_cast<uint16_t>(k << 2));
            x = mba::x_not<uint16_t, Counter ^ 0xE5, 1>(x);
            return mba::x_add<uint16_t, Counter ^ 0xE6, 1>(x, k);
        }
        else {                         // V3 逆
            x = mba::x_xor<uint16_t, Counter ^ 0xE7, 1>(x, static_cast<uint16_t>(k ^ static_cast<uint16_t>(k >> 5)));
            x = static_cast<uint16_t>((x >> 13) | (x << 3));
            return mba::x_sub<uint16_t, Counter ^ 0xE8, 1>(x, k);
        }
    }

    // ── 编译期加密 ──

    template<size_t N, typename Char, uint32_t Counter = 0>
    struct EncryptedString {
        Char data[N];

        static KLI_FORCEINLINE constexpr uint32_t key() {
            return derive_key_irreversible(seed::time_seed(), Counter);
        }

        static KLI_FORCEINLINE constexpr Char arx_encrypt_char(Char c, size_t i) {
            uint32_t k = arx_derive_stream(key(), i);
            if constexpr (sizeof(Char) == 1) {
                return static_cast<Char>(arx_enc_u8<Counter>(static_cast<uint8_t>(c), static_cast<uint8_t>(k & 0xFF)));
            }
            else {
                return static_cast<Char>(arx_enc_u16<Counter>(static_cast<uint16_t>(c), static_cast<uint16_t>(k & 0xFFFF)));
            }
        }

        KLI_FORCEINLINE constexpr EncryptedString(const Char(&str)[N]) : data{} {
            Char prev = 0;
            for (size_t i = 0; i < N; ++i) {
                data[i] = arx_encrypt_char(static_cast<Char>(str[i] ^ prev), i);
                prev = data[i];
            }
        }
    };

    // ── 解密基类 ──

    template<size_t N, typename Char, uint32_t Counter>
    struct DecryptBase {
    protected:
        // 栈布局随机化: cipher_ 和 buffer_ 之间插入 Counter 决定的填充
        // 每个 KLI_SCOPED_* 调用点的栈对象布局不同, 攻击者无法靠固定偏移定位明文
        static constexpr size_t PAD_BYTES = (seed::cx_seed(Counter) & 0x3F);  // 0..63 字节
        Char cipher_[N];      // NOTE: 已被 stable_key_mask 派生流再次异或 (.rdata 形态 != 实际)
        volatile uint8_t pad_[PAD_BYTES + 1];  // +1 防 N=0 时数组为零长
        Char buffer_[N];      // 真明文; 通过 Guard/use(cb)/zero() 控制生命周期最小化
        uint32_t frag_a_;     // (key ^ masked_ct_hash) ^ stable_key_mask()
        uint32_t frag_b_;     // key ^ mix_b(stable_key_mask(), 0xA7)

        // 派生 cipher 异或流: 与 stable_key_mask 绑定, 离线无法预计算
        static KLI_FORCEINLINE Char cipher_xor_stream(uint32_t mk, size_t i) {
            uint32_t s = seed::mix(mk ^ static_cast<uint32_t>(i), Counter ^ 0xB7);
            if constexpr (sizeof(Char) == 1) return static_cast<Char>(s & 0xFF);
            else                             return static_cast<Char>(s & 0xFFFF);
        }

        // 解出 key 并用 frag_a_ 校验已 mask 的 cipher 完整性
        // 篡改 cipher -> ct_hash 不匹配 -> 返回 0 -> 流密钥退化 -> 输出乱码, 明文不泄露
        KLI_FORCEINLINE uint32_t real_key() const {
            uint32_t mask_a = Runtime::stable_key_mask();
            uint32_t mask_b = seed::mix_b(mask_a, 0xA7);
            uint32_t k  = mba::x_xor<uint32_t, Counter ^ 0xC0>(frag_b_, mask_b);
            uint32_t ch = ciphertext_hash<N, Char, Counter>(cipher_);
            uint32_t lhs = mba::x_xor<uint32_t, Counter ^ 0xC1>(frag_a_, mask_a);
            uint32_t rhs = mba::x_xor<uint32_t, Counter ^ 0xC2>(k, ch);
            return (lhs == rhs) ? k : 0;
        }

        KLI_FORCEINLINE Char do_arx_decrypt_char(Char c, size_t i, uint32_t key) const {
            uint32_t k = arx_derive_stream(key, i);
            if constexpr (sizeof(Char) == 1) {
                return static_cast<Char>(arx_dec_u8<Counter>(static_cast<uint8_t>(c), static_cast<uint8_t>(k & 0xFF)));
            }
            else {
                return static_cast<Char>(arx_dec_u16<Counter>(static_cast<uint16_t>(c), static_cast<uint16_t>(k & 0xFFFF)));
            }
        }

        static KLI_FORCEINLINE void secure_zero(void* ptr, size_t len) {
            volatile Char* p = static_cast<volatile Char*>(ptr);
            for (size_t i = 0; i < len; ++i) p[i] = static_cast<Char>(0);
        }

        // 解密前临时反 mask, 解完即刻还原, cipher_ 在内存中始终是 masked 形态
        KLI_FORCEINLINE void decrypt_to_buffer() {
            // real_key 必须在 cipher_ 还是 masked 形态时调用 (与构造时 ct_hash 输入一致)
            uint32_t key = real_key();
            uint32_t mk = Runtime::stable_key_mask();
            // 反 mask
            volatile Char* cv = cipher_;
            for (size_t i = 0; i < N; ++i) cv[i] ^= cipher_xor_stream(mk, i);
            Char prev = 0;
            for (size_t i = 0; i < N; ++i) {
                Char decrypted = do_arx_decrypt_char(cipher_[i], i, key) ^ prev;
                prev = cipher_[i];
                buffer_[i] = decrypted;
            }
            // 重新 mask, 缩短未 mask 窗口
            for (size_t i = 0; i < N; ++i) cv[i] ^= cipher_xor_stream(mk, i);
        }

        struct InitTag {};
        KLI_FORCEINLINE DecryptBase(const EncryptedString<N, Char, Counter>& enc, InitTag) {
            uint32_t mask_a = Runtime::stable_key_mask();
            uint32_t mask_b = seed::mix_b(mask_a, 0xA7);
            uint32_t k  = enc.key();
            // ct_hash 在 masked cipher 上算: 与 real_key() 校验路径一致
            // 从 .rdata 静态密文 (enc.data) 上算 ciphertext_hash 拿不到这个值
            volatile Char* dst = cipher_;
            for (size_t i = 0; i < N; ++i) dst[i] = enc.data[i] ^ cipher_xor_stream(mask_a, i);
            uint32_t ch = ciphertext_hash<N, Char, Counter>(cipher_);
            frag_a_ = mba::x_xor<uint32_t, Counter ^ 0xC3>(mba::x_xor<uint32_t, Counter ^ 0xC4>(k, ch), mask_a);
            frag_b_ = mba::x_xor<uint32_t, Counter ^ 0xC5>(k, mask_b);
            // 填充 volatile 数组阻止编译器优化掉栈占用; 同时让噪声值因
            // mask_a (运行时熵) 而不可预测, 攻击者扫栈找不到固定模式
            for (size_t i = 0; i < sizeof(pad_); ++i) pad_[i] = static_cast<uint8_t>((mask_a >> ((i & 3) * 8)) ^ static_cast<uint8_t>(i));
            for (size_t i = 0; i < N; ++i) buffer_[i] = 0;
        }

        KLI_FORCEINLINE ~DecryptBase() {
            secure_zero(cipher_, N);
            secure_zero(buffer_, N);
            for (size_t i = 0; i < sizeof(pad_); ++i) pad_[i] = 0;
            secure_zero(&frag_a_, sizeof(frag_a_));
            secure_zero(&frag_b_, sizeof(frag_b_));
        }
    };

    // ── 解密接口 ──

    template<size_t N, typename Char, uint32_t Counter>
    struct Decrypt : DecryptBase<N, Char, Counter> {
    private:
        using Base = DecryptBase<N, Char, Counter>;
        bool decrypted_ = false;

    public:
        KLI_FORCEINLINE Decrypt(const EncryptedString<N, Char, Counter>& enc) : Base(enc, InitTag{}) {}

        // 幂等: 已解密直接返回 buffer, 避免重复清零+重解的语义混乱
        // 明文窗口由调用方通过 Guard / use(cb) / zero() 显式控制
        KLI_FORCEINLINE Char* get() {
            if (!decrypted_) {
                Base::decrypt_to_buffer();
                decrypted_ = true;
            }
            return Base::buffer_;
        }

        KLI_FORCEINLINE const Char* get() const {
            return const_cast<Decrypt*>(this)->get();
        }

        // 推荐: 解密 -> 回调 -> 立即清零 (明文窗口最短)
        template<typename Callback>
        KLI_FORCEINLINE auto use(Callback&& cb) -> decltype(cb(static_cast<Char*>(nullptr))) {
            Char* p = get();
            auto result = cb(p);
            Base::secure_zero(Base::buffer_, N);
            decrypted_ = false;
            return result;
        }

        KLI_FORCEINLINE void zero() {
            Base::secure_zero(Base::buffer_, N);
            decrypted_ = false;
        }

        // 隐式转换: 用后自动清零, 避免明文长时间驻留
        struct AutoZeroPtr {
            Char* ptr;
            Decrypt& owner;
            KLI_FORCEINLINE AutoZeroPtr(Char* p, Decrypt& o) : ptr(p), owner(o) {}
            KLI_FORCEINLINE ~AutoZeroPtr() { owner.zero(); }
            KLI_FORCEINLINE operator Char*() { return ptr; }
            KLI_FORCEINLINE operator const Char*() const { return ptr; }
            KLI_FORCEINLINE Char* operator->() { return ptr; }
            KLI_FORCEINLINE Char& operator*() { return *ptr; }
        };

        // RAII 守卫: 解密后作用域结束自动清零, 即使异常抛出也安全
        class Guard {
            Decrypt& owner_;
            Char* ptr_;
        public:
            KLI_FORCEINLINE Guard(Decrypt& o) : owner_(o), ptr_(o.get()) {}
            KLI_FORCEINLINE ~Guard() { owner_.zero(); }
            KLI_FORCEINLINE Char* data() { return ptr_; }
            KLI_FORCEINLINE operator Char*() { return ptr_; }
            KLI_FORCEINLINE Char* operator->() { return ptr_; }
            KLI_FORCEINLINE Char& operator*() { return *ptr_; }
            Guard(const Guard&) = delete;
            Guard& operator=(const Guard&) = delete;
        };

        // 推荐: RAII 守卫访问, 离开作用域自动清零
        KLI_FORCEINLINE Guard guard() { return Guard(*this); }

        KLI_FORCEINLINE AutoZeroPtr operator*() { return AutoZeroPtr(get(), *this); }
        KLI_FORCEINLINE AutoZeroPtr operator->() { return AutoZeroPtr(get(), *this); }
        KLI_FORCEINLINE operator Char*() { return get(); }
        KLI_FORCEINLINE operator const Char*() { return get(); }
    };

    template<size_t N, typename Char, uint32_t Counter>
    KLI_FORCEINLINE Decrypt<N, Char, Counter> make_decrypt(const EncryptedString<N, Char, Counter>& enc) {
        return Decrypt<N, Char, Counter>(enc);
    }

} // namespace crypt
} // namespace KliProtected