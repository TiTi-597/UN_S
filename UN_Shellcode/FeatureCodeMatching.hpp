#define SEARCH_ATTR_EXECUTE  0x01 
#define SEARCH_ATTR_WRITE    0x02
#define SEARCH_ATTR_READ     0x04 

#define WILDCARD_BYTE        0xCC 

__declspec(noinline) NTSTATUS SearchMemoryInProcessEx(PMap Map, PDriverControl Ctrl) {
    if (!Ctrl) return STATUS_INVALID_PARAMETER;

    ULONG64 vAddress = Ctrl->Address;
    ULONG64 vBuffer = Ctrl->Buffer;
    ULONG64 vSize = Ctrl->Size;
    ULONG64 vType = Ctrl->Type;
    ULONG64 vResult = Ctrl->ProcessId;

    if (!vResult || !vSize || !vBuffer || vSize > 512) return STATUS_INVALID_PARAMETER;

    auto fnObOpenObjectByPointer = (decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer);
    auto fnZwClose = (decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose);
    auto fnExAllocatePoolWithTag = (decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag);
    auto fnExFreePoolWithTag = (decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag);
    auto fnZwQueryVirtualMemory = (decltype(ZwQueryVirtualMemory)*)_IT(Map, Map->ImportTable.ZwQueryVirtualMemory);
    auto fnMmCopyVirtualMemory = (NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T))_IT(Map, Map->ImportTable.MmCopyVirtualMemory);
    PVOID SelfEprocess = GetCurrentEprocess(Map);
    PVOID CurrentProcess = Map->Process.CurrentProcess;
    ULONG PoolTag = Map->MEMORY_TAG.TlbN;
    POBJECT_TYPE PsProcessType = *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType);

    if (!MyMmIsAddressValid(Map, (PVOID)vBuffer) || !MyMmIsAddressValid(Map, (PVOID)(vBuffer + vSize - 1))) return STATUS_ACCESS_VIOLATION;

    HANDLE ProcessHandle = NULL;
    NTSTATUS Status = fnObOpenObjectByPointer(CurrentProcess, OBJ_KERNEL_HANDLE, NULL, (ACCESS_MASK)0x0400, PsProcessType, KernelMode, &ProcessHandle);
    if (!NT_SUCCESS(Status)) return Status;

    PUCHAR pPat = (PUCHAR)vBuffer;
    BOOLEAN bWild = FALSE;
    for (SIZE_T i = 0; i < vSize; i++) {
        if (pPat[i] == WILDCARD_BYTE) {
            bWild = TRUE;
            break;
        }
    }

    SIZE_T shift[256], anchor = vSize - 1, secondAnchor = (SIZE_T)-1;
    if (!bWild) {
        for (SIZE_T i = 0; i < 256; i++) shift[i] = vSize;
        for (SIZE_T i = 0; i < vSize - 1; i++) shift[pPat[i]] = vSize - 1 - i;
        if (vSize >= 3) secondAnchor = anchor / 2;
    }
    else {
        while (anchor > 0 && pPat[anchor] == WILDCARD_BYTE) {
            anchor--;
        }
        if (pPat[anchor] == WILDCARD_BYTE) {
            fnZwClose(ProcessHandle);
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T i = 0; i < 256; i++) {
            shift[i] = anchor + 1;
        }
        for (SIZE_T i = 0; i < anchor; i++) {
            if (pPat[i] != WILDCARD_BYTE) {
                SIZE_T s = anchor - i;
                if (s < shift[pPat[i]]) {
                    shift[pPat[i]] = s;
                }
            }
        }
        SIZE_T rightmostWild = (SIZE_T)-1;
        for (SIZE_T i = anchor - 1; i != (SIZE_T)-1; i--) {
            if (pPat[i] == WILDCARD_BYTE) {
                rightmostWild = i;
                break;
            }
        }
        if (rightmostWild != (SIZE_T)-1) {
            SIZE_T wildShift = anchor - rightmostWild;
            for (SIZE_T i = 0; i < 256; i++) {
                if (wildShift < shift[i]) {
                    shift[i] = wildShift;
                }
            }
        }
        for (SIZE_T i = anchor - 1; i != (SIZE_T)-1; i--) {
            if (pPat[i] != WILDCARD_BYTE) {
                secondAnchor = i;
                break;
            }
        }
    }

    SIZE_T BUF = 0x400000, OVERLAP = vSize - 1, PatLen = vSize;
    SIZE_T AnchorOff = anchor, SecondAnchor = secondAnchor;
    PUCHAR pBuf = (PUCHAR)fnExAllocatePoolWithTag(NonPagedPoolNx, BUF + OVERLAP, PoolTag);
    if (!pBuf) {
        fnZwClose(ProcessHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UCHAR attrLut[256];
    attrLut[PAGE_READONLY] = SEARCH_ATTR_READ;
    attrLut[PAGE_READWRITE] = attrLut[PAGE_WRITECOPY] = SEARCH_ATTR_READ | SEARCH_ATTR_WRITE;
    attrLut[PAGE_EXECUTE] = SEARCH_ATTR_EXECUTE;
    attrLut[PAGE_EXECUTE_READ] = SEARCH_ATTR_EXECUTE | SEARCH_ATTR_READ;
    attrLut[PAGE_EXECUTE_READWRITE] = attrLut[PAGE_EXECUTE_WRITECOPY] = SEARCH_ATTR_EXECUTE | SEARCH_ATTR_READ | SEARCH_ATTR_WRITE;

    UCHAR attrFilter = (UCHAR)vType;
    PUCHAR StartAddr = (PUCHAR)vAddress;
    PUCHAR pResult = (PUCHAR)vResult;

#define BM_SEARCH(buf, len, startOff) do { \
        SIZE_T _len = (len), _si = (startOff); if (_len < PatLen) break; \
        SIZE_T _limit = _len - PatLen; \
        while (_si <= _limit) { \
            _mm_prefetch(( char*)(buf) + _si + 64, _MM_HINT_T0); \
            UCHAR _b = (buf)[_si + AnchorOff]; \
            if (_b == pPat[AnchorOff]) { \
                if (SecondAnchor != (SIZE_T)-1 && (buf)[_si + SecondAnchor] != pPat[SecondAnchor]) { \
                    SIZE_T _s2 = shift[(buf)[_si + SecondAnchor]], _d2 = AnchorOff - SecondAnchor; \
                    _si += (_s2 > _d2) ? _s2 - _d2 : 1; continue; } \
                BOOLEAN _ok = TRUE; SIZE_T _mm = 0; \
                if (!bWild) { for (SIZE_T _j = AnchorOff; ; _j--) { \
                    if ((buf)[_si + _j] != pPat[_j]) { _ok = FALSE; _mm = _j; break; } if (!_j) break; } \
                } else { for (SIZE_T _j = AnchorOff; ; _j--) { \
                    if (pPat[_j] != WILDCARD_BYTE && (buf)[_si + _j] != pPat[_j]) { _ok = FALSE; _mm = _j; break; } if (!_j) break; } } \
                if (_ok) { PUCHAR _ma = tailBase + _si; \
                    if (_ma != StartAddr) { Found = _ma; break; } _si++; continue; } \
                { SIZE_T _s = shift[(buf)[_si + _mm]], _d = AnchorOff - _mm; _si += (_s > _d) ? _s - _d : 1; } \
            } else { _si += shift[_b]; } \
        } \
    } while(0)

#define RETAIN_TAIL(n) do { \
        SIZE_T _n = (n) > OVERLAP ? OVERLAP : (n); \
        volatile UCHAR* _src = pBuf + tailLen + (n) - _n; \
        volatile UCHAR* _dst = pBuf; \
        for (SIZE_T _k = 0; _k < _n; _k++) _dst[_k] = _src[_k]; \
        tailLen = _n; \
    } while(0)

    PUCHAR Found = NULL, SearchAddr = vAddress ? (PUCHAR)vAddress : (PUCHAR)0x10000;
    PUCHAR LIMIT = (PUCHAR)0x7FFFFFFFFFFF;

    while (!Found && SearchAddr < LIMIT) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!NT_SUCCESS(fnZwQueryVirtualMemory(ProcessHandle, SearchAddr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL))) {
            SearchAddr += 0x10000;
            continue;
        }

        PUCHAR RegionBase = (PUCHAR)mbi.BaseAddress, RegionEnd = RegionBase + mbi.RegionSize;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & 0xFF) == PAGE_NOACCESS ||
            (attrFilter && (attrLut[mbi.Protect & 0xFF] & attrFilter) != attrFilter)) {
            SearchAddr = RegionEnd;
            continue;
        }

        PUCHAR Addr = (SearchAddr > RegionBase) ? SearchAddr : RegionBase, tailBase = Addr;
        SIZE_T tailLen = 0;

        while (!Found && Addr < RegionEnd) {
            SIZE_T Remaining = (SIZE_T)(RegionEnd - Addr);
            if (Remaining < PatLen) break;
            SIZE_T ToRead = (Remaining < BUF) ? Remaining : BUF, Read = 0;

            Status = fnMmCopyVirtualMemory(CurrentProcess, Addr, SelfEprocess, pBuf + tailLen, ToRead, KernelMode, &Read);

            if (NT_SUCCESS(Status) && Read >= PatLen) {
                BM_SEARCH(pBuf, tailLen + Read, tailLen > OVERLAP ? tailLen - OVERLAP : 0);
                if (Found) break;
                RETAIN_TAIL(Read);
                tailBase = Addr + Read - tailLen;
                Addr += Read;
            }
            else {
                for (SIZE_T pageOff = 0; pageOff < ToRead && !Found; pageOff += 0x1000) {
                    SIZE_T chunkSize = (ToRead - pageOff < 0x1000) ? ToRead - pageOff : 0x1000, chunkRead = 0;
                    NTSTATUS s = fnMmCopyVirtualMemory(CurrentProcess, Addr + pageOff, SelfEprocess, pBuf + tailLen, chunkSize, KernelMode, &chunkRead);
                    if (NT_SUCCESS(s) && chunkRead > 0) {
                        if (tailLen + chunkRead >= PatLen) BM_SEARCH(pBuf, tailLen + chunkRead, tailLen > OVERLAP ? tailLen - OVERLAP : 0);
                        if (Found) break;
                        RETAIN_TAIL(chunkRead);
                        tailBase = Addr + pageOff + chunkRead - tailLen;
                    }
                    else {
                        tailLen = 0;
                        tailBase = Addr + pageOff + chunkSize;
                    }
                }
                if (Found) break;
                Addr += ToRead;
                if (tailBase + tailLen != Addr) {
                    tailLen = 0;
                    tailBase = Addr;
                }
            }
        }
        SearchAddr = RegionEnd;
    }

#undef BM_SEARCH
#undef RETAIN_TAIL

    fnExFreePoolWithTag(pBuf, PoolTag);
    fnZwClose(ProcessHandle);

    if (Found && Found != StartAddr) {
        if (MyMmIsAddressValid(Map, (PVOID)pResult) && MyMmIsAddressValid(Map, (PVOID)(pResult + sizeof(ULONG64) - 1))) {
            *(PULONG64)pResult = (ULONG64)Found;
            return STATUS_SUCCESS;
        }
        return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_NOT_FOUND;
}