using CtDosHeader = KliProtected::detail::KLI_IMAGE_DOS_HEADER;
using CtNtHeaders64 = KliProtected::detail::KLI_IMAGE_NT_HEADERS64;

typedef struct _CT_IMAGE_SECTION_HEADER {
	UCHAR  Name[8];
	union { 
		ULONG PhysicalAddress; 
		ULONG VirtualSize; 
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
} CT_IMAGE_SECTION_HEADER, *PCT_IMAGE_SECTION_HEADER;

struct PiDDBCacheEntry {
	LIST_ENTRY List;
	UNICODE_STRING DriverName;
	ULONG TimeDateStamp;
	NTSTATUS LoadStatus;
	CHAR _0x0028[16];
};

#define _ES_PiDDBLock_w10  "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24"
#define _ES_PiDDBLock_w11  "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x00\x00\x00\x00\x00\xB2\x01\x66\xFF\x00\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C"
#define _ES_PiDDBCache_w10 "\x66\x03\xD2\x48\x8D\x0D"
#define _ES_PiDDBCache_w11 "\x66\x03\x00\x48\x8D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x24\x00\x8B\x46\x08\x89\x44\x24\x40\xE8\x00\x00\x00\x00\x00\x85\xC0\x75\x1B"
#define _ES_BucketPat_21H1  "\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24"
#define _ES_BucketMask_21H1 "\x01\x01\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x01\x01"
#define _ES_BucketPat_22H2  "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"
#define _ES_BucketMask_22H2 "\x01\x01\x01\x00\x00\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01"

static __forceinline PVOID CtResolveRel(PVOID inst, ULONG offOff, ULONG instSize) {
	return (PVOID)((ULONG_PTR)inst + instSize + *(PLONG)((ULONG_PTR)inst + offOff));
}

static __forceinline PCT_IMAGE_SECTION_HEADER CtGetSections(PCHAR base, USHORT& count) {
	auto* dos = (CtDosHeader*)base;
	if (dos->e_magic != KLI_OBFUSCATE_CALL(KliProtected::obf_const::dos_sig)()) return nullptr;
	auto* nt = (CtNtHeaders64*)(base + dos->e_lfanew);
	if (nt->Signature != KLI_OBFUSCATE_CALL(KliProtected::obf_const::pe_sig)()) return nullptr;
	count = nt->FileHeader.NumberOfSections;
	return (PCT_IMAGE_SECTION_HEADER)((ULONG_PTR)nt + offsetof(CtNtHeaders64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
}

static __forceinline PVOID CtFindPattern(PUCHAR base, DWORD len, const UCHAR* pat, const UCHAR* mask, DWORD plen) {
	if (len < plen) return 0;
	for (DWORD i = 0; i <= len - plen; ++i) {
		BOOL ok = TRUE;
		for (DWORD j = 0; j < plen && ok; ++j) {
			if (mask) { 
				if (mask[j] == 1 && base[i + j] != pat[j]) ok = FALSE;
			}
			else { 
				if (pat[j] && base[i + j] != pat[j]) ok = FALSE; 
			}
		}
		if (ok) return &base[i];
	}
	return 0;
}

static __forceinline PVOID CtScanImage(PCHAR base, ULONG secId, const UCHAR* pat, const UCHAR* mask, DWORD plen) {
	USHORT count;
	auto* sec = KLI_OBFUSCATE_CALL(CtGetSections)(base, count);
	if (!sec) return 0;
	for (DWORD i = 0; i < count; ++i) {
		ULONG name4 = *(PINT)sec[i].Name;
		if (secId ? name4 == secId : (name4 == KLI_OBF_CONST(ULONG, 'EGAP') || name4 == KLI_OBF_CONST(ULONG, 0x7865742E))) {
			PVOID r = KLI_OBFUSCATE_CALL(CtFindPattern)((PUCHAR)base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, pat, mask, plen);
			if (r) return r;
		}
	}
	return 0;
}

static __forceinline NTSTATUS CtScanKernelSection(ULONG64 ntBase, ULONG secId, const UCHAR* pat, ULONG_PTR len, PVOID* out) {
	*out = KLI_OBFUSCATE_CALL(CtScanImage)((PCHAR)ntBase, secId, pat, nullptr, (DWORD)len);
	return *out ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static __declspec(noinline) BOOL CtLocatePiDDB(ULONG64 ntBase, PERESOURCE* lock, PRTL_AVL_TABLE* table) {
	SPOOF_FUNC

	PVOID lockPtr = nullptr, cachePtr = nullptr;

	auto sig_lock_w10  = KLI_SCOPED_ASTR(_ES_PiDDBLock_w10);
	auto sig_lock_w11  = KLI_SCOPED_ASTR(_ES_PiDDBLock_w11);
	auto sig_cache_w10 = KLI_SCOPED_ASTR(_ES_PiDDBCache_w10);
	auto sig_cache_w11 = KLI_SCOPED_ASTR(_ES_PiDDBCache_w11);

	auto trySig = [&](const UCHAR* pat1, DWORD len1, ULONG off1, const UCHAR* pat2, DWORD len2, ULONG off2, PVOID* out) -> bool {
		if (NT_SUCCESS(KLI_OBFUSCATE_CALL(CtScanKernelSection)(ntBase, 'EGAP', pat1, len1, out))) return *out = (PVOID)((uintptr_t)*out + off1), true;
		if (NT_SUCCESS(KLI_OBFUSCATE_CALL(CtScanKernelSection)(ntBase, 'EGAP', pat2, len2, out))) return *out = (PVOID)((uintptr_t)*out + off2), true;
		return false;
	};

	if (!trySig((const UCHAR*)sig_lock_w10.get(), sizeof(_ES_PiDDBLock_w10) - 1, 28, (const UCHAR*)sig_lock_w11.get(), sizeof(_ES_PiDDBLock_w11) - 1, 19, &lockPtr)) return false;
	if (!trySig((const UCHAR*)sig_cache_w10.get(), sizeof(_ES_PiDDBCache_w10) - 1, 3, (const UCHAR*)sig_cache_w11.get(), sizeof(_ES_PiDDBCache_w11) - 1, 13, &cachePtr)) return false;

	*lock  = (PERESOURCE)KLI_OBFUSCATE_CALL(CtResolveRel)(lockPtr, 3, 7);
	*table = (PRTL_AVL_TABLE)KLI_OBFUSCATE_CALL(CtResolveRel)(cachePtr, 3, 7);
	return true;
}

static __declspec(noinline) BOOL ClearPiDDBCache(ULONG64 NT_Base, UNICODE_STRING DriverName) {
	SPOOF_FUNC;

	PERESOURCE PiDDBLock = nullptr;
	PRTL_AVL_TABLE PiDDBCacheTable = nullptr;
	if (!KLI_OBFUSCATE_CALL(CtLocatePiDDB)(NT_Base, &PiDDBLock, &PiDDBCacheTable)) return FALSE;

	auto _ExAcquireResourceExclusiveLite = KLI_FN(NT_Base, ExAcquireResourceExclusiveLite);
	auto _ExReleaseResourceLite = KLI_FN(NT_Base, ExReleaseResourceLite);
	auto _RtlEnumerateGenericTableAvl = KLI_FN(NT_Base, RtlEnumerateGenericTableAvl);
	auto _RtlDeleteElementGenericTableAvl = KLI_FN(NT_Base, RtlDeleteElementGenericTableAvl);
	auto _RtlCompareUnicodeString = KLI_FN(NT_Base, RtlCompareUnicodeString);

	if (!_ExAcquireResourceExclusiveLite || !_ExReleaseResourceLite || !_RtlEnumerateGenericTableAvl || !_RtlDeleteElementGenericTableAvl || !_RtlCompareUnicodeString) return FALSE;

	KLI_OBFUSCATE_CALL(_ExAcquireResourceExclusiveLite)(PiDDBLock, TRUE);

	PiDDBCacheEntry* pFoundEntry = nullptr;
	BOOLEAN restart = TRUE;
	for (;;) {
		auto pEntry = (PiDDBCacheEntry*)KLI_OBFUSCATE_CALL(_RtlEnumerateGenericTableAvl)(PiDDBCacheTable, restart);
		if (!pEntry) break;
		restart = FALSE;
		if (pEntry->DriverName.Buffer && pEntry->DriverName.Length > 0 &&
		    KLI_OBFUSCATE_CALL(_RtlCompareUnicodeString)(&pEntry->DriverName, &DriverName, TRUE) == 0) {
			pFoundEntry = pEntry;
			break;
		}
	}

	if (!pFoundEntry) {
		KLI_OBFUSCATE_CALL(_ExReleaseResourceLite)(PiDDBLock);
		return FALSE;
	}

	KLI_OBFUSCATE_CALL(RemoveEntryList)(&pFoundEntry->List);
	KLI_OBFUSCATE_CALL(_RtlDeleteElementGenericTableAvl)(PiDDBCacheTable, pFoundEntry);
	KLI_OBFUSCATE_CALL(_ExReleaseResourceLite)(PiDDBLock);
	return TRUE;
}

static __forceinline wchar_t* CtWcsStr(const wchar_t* str, const wchar_t* sub) {
	if (!sub || !*sub) return (wchar_t*)str;
	for (; *str; str++) {
		const wchar_t* s = str, * p = sub;
		while (*s && *p && *s == *p) { s++; p++; }
		if (!*p) return (wchar_t*)str;
	}
	return nullptr;
}

static __declspec(noinline) BOOL ClearHashBucket(PDRIVER_OBJECT DriverObject, ULONG64 NT_Base, UNICODE_STRING DriverName) {
	SPOOF_FUNC;

	PVOID ciBase = FindBase(DriverObject, "CI.dll", nullptr);
	if (!ciBase) return FALSE;

	auto sig_pat_21h1  = KLI_SCOPED_ASTR(_ES_BucketPat_21H1);
	auto sig_mask_21h1 = KLI_SCOPED_ASTR(_ES_BucketMask_21H1);
	auto sig_pat_22h2  = KLI_SCOPED_ASTR(_ES_BucketPat_22H2);
	auto sig_mask_22h2 = KLI_SCOPED_ASTR(_ES_BucketMask_22H2);

	PVOID sig = KLI_OBFUSCATE_CALL(CtScanImage)((PCHAR)ciBase, 0, (const UCHAR*)sig_pat_21h1.get(), (const UCHAR*)sig_mask_21h1.get(), sizeof(_ES_BucketPat_21H1) - 1);
	if (!sig) sig = KLI_OBFUSCATE_CALL(CtScanImage)((PCHAR)ciBase, 0, (const UCHAR*)sig_pat_22h2.get(), (const UCHAR*)sig_mask_22h2.get(), sizeof(_ES_BucketPat_22H2) - 1);
	if (!sig) return FALSE;

	auto* buckets = (ULONGLONG*)KLI_OBFUSCATE_CALL(CtResolveRel)(sig, 3, 7);
	if (!buckets) return FALSE;

	int regs[4]; __cpuid(regs, 1);
	ULONG hashSeed = KLI_OBFUSCATE_CALL(KliProtected::seed::mix)(MBA_XOR(ULONG, static_cast<ULONG>(MBA_XOR(INT, regs[0], regs[3])), KLI_OBFUSCATE_CALL(KliProtected::seed::time_seed)()), __COUNTER__);

	ULONG matchCount = 0;
	ULONGLONG* pNext = buckets;
	while (*pNext) {
		ULONGLONG current = *pNext;
		auto* name = PWCH(current + 0x48);
		if (name && DriverName.Buffer && KLI_OBFUSCATE_CALL(CtWcsStr)(name, DriverName.Buffer)) {
			*pNext = *(ULONGLONG*)current;
			PUCHAR hashPtr = (PUCHAR)current + 0x18;
			for (int j = 0; j < 20; j++) {
				hashPtr[j] = (UCHAR)KLI_OBFUSCATE_CALL(KliProtected::seed::mix)(MBA_XOR(ULONG, hashSeed, (ULONG)(current + j + 1)), __COUNTER__);
			}
			matchCount++;
		} 
		else {
			pNext = (ULONGLONG*)current;
		}
	}
	return matchCount > 0;
}