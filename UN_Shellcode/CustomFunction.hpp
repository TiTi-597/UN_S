__forceinline ULONG64 DeriveKey(ULONG64 addr) {
	ULONG64 k = addr;
	ULONG64 c1 = (k ^ (k >> 32)) | 1;
	ULONG64 c2 = (k ^ (k << 32)) | 1;
	k ^= (k >> 12);
	k *= c1;
	k ^= (k >> 27);
	k *= c2;
	k ^= (k >> 33);
	return k;
}

__forceinline VOID XorDecrypt(PUCHAR data, SIZE_T dataSize, CONST CHAR* key, SIZE_T keyLen) {
	if (!data || !key || keyLen == 0 || dataSize == 0) return;
	for (SIZE_T i = 0; i < dataSize; i++) {
		data[i] = data[i] ^ (UCHAR)key[i % keyLen];
	}
}

__forceinline ULONG64 _IT(PMap Map, ULONG64 encVal) {
	ULONG64 tagMix = (ULONG64)Map->MEMORY_TAG.llhS | ((ULONG64)Map->MEMORY_TAG.yKeV << 32);
	return encVal ^ DeriveKey((ULONG64)Map ^ tagMix);
}

__forceinline PVOID GetCurrentEprocess(PMap Map) {
	return *(PVOID*)(__readgsqword(0x188) + (ULONG)_IT(Map, Map->System.KThreadApcProcessOffset));
}

__forceinline PVOID GetEprocessPeb(PMap Map, PVOID Process) {
	return *(PVOID*)((PUCHAR)Process + (ULONG)_IT(Map, Map->System.EprocessPebOffset));
}

__forceinline BOOLEAN MyMmIsAddressValid(PMap Map, PVOID Va) {
	ULONG64 va = (ULONG64)Va;
	if (va < 0x1000) return FALSE;

	ULONG64 hi = va >> 47;
	if (hi != 0 && hi != 0x1FFFF) return FALSE;

	ULONG64 pteBase = _IT(Map, Map->System.PteBase);
	if (!pteBase) return FALSE;

	ULONG64 pte = pteBase + ((va  >> 9) & 0x7FFFFFFFF8ULL);
	ULONG64 pde = pteBase + ((pte >> 9) & 0x7FFFFFFFF8ULL);
	ULONG64 ppe = pteBase + ((pde >> 9) & 0x7FFFFFFFF8ULL);
	ULONG64 pxe = pteBase + ((ppe >> 9) & 0x7FFFFFFFF8ULL);

	if ((*(PULONG64)pxe & 1) == 0) return FALSE;
	if ((*(PULONG64)ppe & 1) == 0) return FALSE;
	if (*(PULONG64)ppe & (1ULL << 7)) return TRUE;
	if ((*(PULONG64)pde & 1) == 0) return FALSE;
	if (*(PULONG64)pde & (1ULL << 7)) return TRUE;
	if ((*(PULONG64)pte & 1) == 0) return FALSE;
	return TRUE;
}

__forceinline KIRQL RaiseIrql(KIRQL NewIrql) {
    KIRQL result = (KIRQL)__readcr8();
    __writecr8(NewIrql);
    return result;
}

__forceinline VOID LowerIrql(KIRQL NewIrql) {
    __writecr8(NewIrql);
}

__forceinline VOID AcquireSpinLock(PKSPIN_LOCK spinLock) {
	while (_InterlockedCompareExchange((volatile LONG*)spinLock, 1, 0) != 0) {
		_mm_pause();
	}
	_ReadWriteBarrier();
}

__forceinline VOID ReleaseSpinLock(PKSPIN_LOCK spinLock) {
	_ReadWriteBarrier();
	_InterlockedExchange((volatile LONG*)spinLock, 0);
}