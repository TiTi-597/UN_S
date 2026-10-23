__forceinline BOOLEAN ValidatePageTableChain(InvlpgCopyMemoryParameters* params, PVOID va, ULONG64 cr3Phys) {
	ULONG64 tablePhys = cr3Phys;
	for (INT lvl = 3; lvl >= 0; lvl--) {
		ULONG64 entry = InvlpgReadPte(params, tablePhys + 8 * (((ULONG64)(va) >> (12 + 9 * (lvl))) & 0x1FF));
		if (!(entry & 1)) return FALSE;
		tablePhys = (((entry) >> 12) & 0xFFFFFFFFFULL) << 12;
	}
	return TRUE;
}

__forceinline VOID InitCopyParams(InvlpgCopyMemoryParameters* params, PMap Map, INT threadIndex) {
	InvlpgInitSlots(params, _IT(Map, Map->System.Ptes), _IT(Map, Map->System.PtesPte), threadIndex);
	params->PageOffset = 0;
	params->RemainSize = PAGE_SIZE;
}

__forceinline VOID CleanupCopyParams(InvlpgCopyMemoryParameters* params, KIRQL kirql, PMap Map, INT threadIndex) {
	InvlpgCleanupSlots(params);
	LowerIrql(kirql);
	_enable();
	_InterlockedExchange8(&Map->Thread.threadUseMap[threadIndex], FALSE);
}

__declspec(noinline) ULONG64 dirbase_from_base_address(PMap Map, PVOID base) {
	INT threadIndex = GetThreadUniqueIndexFromMap(Map, PAGE_SIZE);
	if (threadIndex == -1) return 0;

	InvlpgCopyMemoryParameters params;
	InitCopyParams(&params, Map, threadIndex);

	_disable();
	KIRQL kirql = RaiseIrql(DISPATCH_LEVEL);

	PPHYSICAL_MEMORY_RANGE ranges = (PPHYSICAL_MEMORY_RANGE)_IT(Map, Map->System.PhysMemRanges);
	ULONG rangeCount = Map->System.PhysMemRangeCount;
	ULONG64 result = 0;

	if (!ranges || !rangeCount) {
		CleanupCopyParams(&params, kirql, Map, threadIndex);
		return 0;
	}
	ULONG64 pfnBase = _IT(Map, Map->Process.MmPfnDataBase);
	for (ULONG i = 0; i < rangeCount; i++) {
		auto elem = &ranges[i];
		if (!elem->NumberOfBytes.QuadPart) break;

		ULONG64 physAddr = elem->BaseAddress.QuadPart;
		ULONG64 pageCount = elem->NumberOfBytes.QuadPart / PAGE_SIZE;

		for (ULONG64 j = 0; j < pageCount; j++, physAddr += PAGE_SIZE) {
			ULONG64 pfnEntry = *(ULONG64*)((uintptr_t)pfnBase + (physAddr >> 12) * 48 + 40);
			if ((pfnEntry & 0xFFFFFFFFFFULL) != (physAddr >> 12)) continue;

			if (ValidatePageTableChain(&params, base, physAddr)) {
				result = physAddr;
				break;
			}
		}
		if (result) break;
	}

	CleanupCopyParams(&params, kirql, Map, threadIndex);
	return result;
}