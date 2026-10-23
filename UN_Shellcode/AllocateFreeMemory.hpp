struct PageTableAddrs {
	ULONG64 pml4e;
	ULONG64 pdpte;
	ULONG64 pde;
	ULONG64 pte;
};

struct PrealloCtx {
	PVOID* pages;
	ULONG64* phys;
	ULONG total;
	ULONG used;
};

struct ProcessContext {
	ULONG64 oldCr3;
	BOOLEAN interruptsEnabled;
};

__forceinline PVOID _Alloc(PMap Map, SIZE_T sz, ULONG tag) {
	return ((decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPoolNx, sz, tag);
}

__forceinline VOID _Free(PMap Map, PVOID p, ULONG tag) {
	((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(p, tag);
}

__forceinline BOOLEAN IsKernelPtr(PVOID addr) {
	return addr && ((ULONG64)addr >> 63) != 0;
}

__forceinline NTSTATUS KeSleep(PMap Map, ULONG ms) {
	if (ms > MAXLONG / 10000) return STATUS_INVALID_PARAMETER;
	LARGE_INTEGER delay; delay.QuadPart = -(LONGLONG)ms * 10000;
	return ((decltype(KeDelayExecutionThread)*)_IT(Map, Map->ImportTable.KeDelayExecutionThread))(KernelMode, FALSE, &delay);
}

__declspec(noinline) ULONG64 SecureRandom(PMap Map) {
	ULONG64 tsc = __rdtsc();
	ULONG64 ptr = (ULONG64)GetCurrentEprocess(Map);
	ULONG64 ptr2 = __readgsqword(0x188);
	tsc ^= (ptr  << 13) | (ptr  >> 17);
	tsc ^= (ptr2 <<  7) | (ptr2 >> 23);
	tsc ^= _IT(Map, Map->System.PteBase);
	tsc ^= tsc >> 33; tsc *= ptr  | 1;
	tsc ^= tsc >> 29; tsc *= ptr2 | 1;
	return tsc ^ (tsc >> 32);
}

__forceinline UCHAR RandomWsIndex(PMap Map, UCHAR level) {
	static const UCHAR base[] = { 0x07, 0x08, 0x09 };
	return base[level % 3] ^ (UCHAR)(SecureRandom(Map) & 0x03) ^ (level & 0x01);
}

__forceinline ULONG RandomRetryCount(PMap Map, ULONG base, ULONG range) {
	return range ? base + (ULONG)(SecureRandom(Map) % range) : base;
}

__declspec(noinline) ULONG64 GetRandomBaseAddress(PMap Map, SIZE_T Size) {
	ULONG64 userTop = (1ULL << 47) - 1;
	ULONG64 base = (userTop - (userTop >> 4)) + ((SecureRandom(Map) % 8) << 36);
	if (Size >= base) return 0;
	ULONG64 maxOff = base - Size;
	ULONG64 randOff = (SecureRandom(Map) % 0x20000) << 16;
	if (randOff > maxOff) randOff = (maxOff >> 16) << 16;
	ULONG64 start = (base - Size - randOff) & ~0xFFFULL;
	return start >= 0x10000 ? start : 0;
}

__forceinline VOID FlushTlbRange(ULONG64 start, ULONG64 size) {
	if (!size) return;
	ULONG64 pages = (size + 0xFFF) >> 12;
	for (ULONG64 i = 0; i < pages; i++) __invlpg((PVOID)(start + (i << 12)));
}

__forceinline VOID GetAllPageTableAddrs(PMap Map, ULONG64 va, PageTableAddrs* out) {
	ULONG64 pb = _IT(Map, Map->System.PteBase);
	out->pte = ((va >> 9) & 0x7FFFFFFFF8) + pb;
	out->pde = ((out->pte >> 9) & 0x7FFFFFFFF8) + pb;
	out->pdpte = ((out->pde >> 9) & 0x7FFFFFFFF8) + pb;
	out->pml4e = ((out->pdpte >> 9) & 0x7FFFFFFFF8) + pb;
}

__declspec(noinline) ULONG64 MmiGetPhysicalAddress(PMap Map, PVOID va) {
	PageTableAddrs a; GetAllPageTableAddrs(Map, (ULONG64)va, &a);
	if (!IsKernelPtr((PVOID)a.pml4e)) return 0;
	HardwarePteX64 p;
	p.all = *(PULONG64)a.pml4e; 
	if (!p.valid || p.large_page) return 0;
	p.all = *(PULONG64)a.pdpte; 
	if (!p.valid) return 0;
	if (p.large_page) return (p.page_frame_number << 12) + ((ULONG64)va & 0x3FFFFFFF);
	p.all = *(PULONG64)a.pde;  
	if (!p.valid) return 0;
	if (p.large_page) return (p.page_frame_number << 12) + ((ULONG64)va & 0x1FFFFF);
	p.all = *(PULONG64)a.pte;  
	if (!p.valid) return 0;
	return (p.page_frame_number << 12) + ((ULONG64)va & 0xFFF);
}

__declspec(noinline) BOOLEAN PreallocFill(PMap Map, PrealloCtx* pc, ULONG count) {
	pc->pages = (PVOID*)_Alloc(Map, sizeof(PVOID) * count, Map->MEMORY_TAG.yKeV);
	if (!pc->pages) return FALSE;
	pc->phys = (ULONG64*)_Alloc(Map, sizeof(ULONG64) * count, Map->MEMORY_TAG.yKeV);
	if (!pc->phys) {
		_Free(Map, pc->pages, Map->MEMORY_TAG.yKeV);
		pc->pages = NULL;
		return FALSE;
	}
	pc->total = 0; pc->used = 0;
	ULONG maxRetry = RandomRetryCount(Map, 10, 15);
	for (ULONG c = 0; c < count; c++) {
		PVOID addr = NULL;
		for (ULONG i = 0; i < maxRetry; i++) {
			addr = _Alloc(Map, 0x1000, Map->MEMORY_TAG.yKeV);
			if (!addr) { 
				KeSleep(Map, 50); 
				continue;
			}
			if ((ULONG64)addr & 0xFFF) {
				_Free(Map, addr, Map->MEMORY_TAG.yKeV);
				addr = NULL;
				KeSleep(Map, 50);
				continue;
			}
			__stosb((PUCHAR)addr, 0, 0x1000);
			ULONG64 phy = MmiGetPhysicalAddress(Map, addr);
			if (!phy) {
				_Free(Map, addr, Map->MEMORY_TAG.yKeV);
				addr = NULL; 
				KeSleep(Map, 50);
				continue;
			}
			pc->pages[c] = addr;
			pc->phys[c] = phy;
			pc->total++;
			break;
		}
		if (!addr) return FALSE;
	}
	return TRUE;
}

__declspec(noinline) HardwarePteX64 TakePreallocPage(PrealloCtx* pc, PVOID* ppool) {
	HardwarePteX64 pte = { 0 };
	*ppool = NULL;
	if (pc->used >= pc->total) return pte;
	ULONG i = pc->used++;
	pte.page_frame_number = pc->phys[i] >> 12;
	pte.valid = 1; pte.write = 1; pte.owner = 1;
	*ppool = pc->pages[i];
	return pte;
}

__declspec(noinline) VOID PreallocReleaseRange(PMap Map, PrealloCtx* pc, ULONG fromIdx) {
	if (!pc->pages) return;
	for (ULONG i = fromIdx; i < pc->total; i++) {
		if (pc->pages[i]) _Free(Map, pc->pages[i], Map->MEMORY_TAG.yKeV);
	}
	_Free(Map, pc->pages, Map->MEMORY_TAG.yKeV);
	_Free(Map, pc->phys,  Map->MEMORY_TAG.yKeV);
	pc->pages = NULL;
	pc->phys = NULL;
	pc->total = 0;
	pc->used = 0;
}

__forceinline VOID PreallocReleaseUnused(PMap Map, PrealloCtx* pc) {
	PreallocReleaseRange(Map, pc, pc->used);
}

__forceinline VOID PreallocReleaseAll(PMap Map, PrealloCtx* pc) {
	PreallocReleaseRange(Map, pc, 0);
}

__declspec(noinline) BOOLEAN IsAddressRangeOverlap(MemAllocTable* table, ULONG64 addr, SIZE_T size) {
	if (!table || !table->entries) return FALSE;
	ULONG64 end = addr + size;
	if (end < addr) return TRUE;
	for (INT i = 0; i < table->capacity; i++) {
		if (!table->entries[i].inUse) continue;
		ULONG64 eAddr = table->entries[i].address;
		ULONG64 eEnd = eAddr + table->entries[i].size;
		if (addr < eEnd && end > eAddr) return TRUE;
	}
	return FALSE;
}

__declspec(noinline) BOOLEAN ExpandBuffer(PMap Map, PVOID* buf, INT* cap, INT itemSize, ULONG tag) {
	INT newCap = *cap * 2;
	if (newCap > 16384) newCap = 16384;
	if (newCap <= *cap) return FALSE;
	PVOID newBuf = _Alloc(Map, itemSize * newCap, tag);
	if (!newBuf) return FALSE;
	__stosb((PUCHAR)newBuf, 0, itemSize * newCap);
	if (*buf && *cap > 0) {
		__movsb((PUCHAR)newBuf, (PUCHAR)*buf, itemSize * *cap);
		_Free(Map, *buf, tag);
	}
	*buf = newBuf; 
	*cap = newCap;
	return TRUE;
}

__forceinline VOID ClearAllocItemPte(AllocItem* item) {
	if (item->pPageEntry && IsKernelPtr(item->pPageEntry)) *(ULONG64*)item->pPageEntry = 0;
}

__declspec(noinline) VOID FreeAllocItem(PMap Map, AllocItem* item, BOOLEAN isProcessActive, BOOLEAN isRollback) {
	if (isRollback || item->type >= 1) {
		if (isProcessActive) ClearAllocItemPte(item);
		if (item->poolAddr && IsKernelPtr(item->poolAddr)) _Free(Map, item->poolAddr, Map->MEMORY_TAG.yKeV);
	}
	item->pPageEntry = NULL;
	item->poolAddr = NULL;
	item->type = 0;
}

__declspec(noinline) PVOID NewHistory(PMap Map, INT cap) {
	if (cap <= 0) cap = 256;
	PageHistory* p = (PageHistory*)_Alloc(Map, sizeof(PageHistory), Map->MEMORY_TAG.News);
	if (!p) return NULL;
	__stosb((PUCHAR)p, 0, sizeof(PageHistory));
	p->his = (AllocItem*)_Alloc(Map, sizeof(AllocItem) * cap, Map->MEMORY_TAG.AlcI);
	if (!p->his) {
		_Free(Map, p, Map->MEMORY_TAG.News);
		return NULL;
	}
	__stosb((PUCHAR)p->his, 0, sizeof(AllocItem) * cap);
	p->capacity = cap;
	return p;
}

__declspec(noinline) VOID FreePageHistory(PMap Map, PVOID a_his, BOOLEAN isProcessActive, BOOLEAN isRollback) {
	if (!a_his) return;
	PageHistory* his = (PageHistory*)a_his;
	if (his->his) {
		for (INT i = his->cnt - 1; i >= 0; i--) FreeAllocItem(Map, &his->his[i], isProcessActive, isRollback);
		_Free(Map, his->his, Map->MEMORY_TAG.AlcI);
	}
	_Free(Map, his, Map->MEMORY_TAG.News);
}

__forceinline BOOLEAN EnsureHistoryCapacity(PMap Map, PageHistory* his, INT need) {
	while (his->capacity - his->cnt < need) {
		if (!ExpandBuffer(Map, (PVOID*)&his->his, &his->capacity, sizeof(AllocItem), Map->MEMORY_TAG.AlcI)) return FALSE;
	}
	return TRUE;
}

__declspec(noinline) BOOLEAN AllocAndOverWritePte(PMap Map, ULONG64 Address, PageHistory* his, PrealloCtx* pc) {
	PageTableAddrs addrs; GetAllPageTableAddrs(Map, Address, &addrs);
	struct { ULONG64* entry; UCHAR level; INT type; } levels[] = {
		{ (ULONG64*)addrs.pml4e, 0, 4 },
		{ (ULONG64*)addrs.pdpte, 1, 3 },
		{ (ULONG64*)addrs.pde,   2, 2 },
		{ (ULONG64*)addrs.pte,   3, 1 },
	};
	for (INT i = 0; i < 4; i++) {
		if (*levels[i].entry) continue;
		if (his->cnt >= his->capacity) return FALSE;
		PVOID pool = NULL;
		HardwarePteX64 pte = TakePreallocPage(pc, &pool);
		if (!pool) return FALSE;
		if (levels[i].level < 3) pte.software_ws_index = RandomWsIndex(Map, levels[i].level);
		*levels[i].entry = pte.all;
		his->his[his->cnt++] = { (ULONG)levels[i].type, (HardwarePteX64*)levels[i].entry, pool };
	}
	return TRUE;
}

__declspec(noinline) BOOLEAN MakeR3Memory(PMap Map, ULONG64 start, ULONG64 size, PVOID a_his, PrealloCtx* pc) {
	PageHistory* his = (PageHistory*)a_his;
	ULONG64 pages = size >> 12;
	INT startCnt = his->cnt;
	ULONG startUsed = pc->used;
	for (ULONG64 i = 0; i < pages; i++) {
		if (!AllocAndOverWritePte(Map, start + (i << 12), his, pc)) {
			for (INT j = his->cnt - 1; j >= startCnt; j--) {
				if (his->his[j].pPageEntry) *(ULONG64*)his->his[j].pPageEntry = 0;
				his->his[j].pPageEntry = NULL;
				his->his[j].poolAddr = NULL;
				his->his[j].type = 0;
			}
			his->cnt = startCnt;
			pc->used = startUsed;
			return FALSE;
		}
	}
	FlushTlbRange(start, size);
	return TRUE;
}

__declspec(noinline) BOOLEAN FreeR3Memory(PMap Map, ULONG64 start, ULONG64 size) {
	if (!start || !size) return FALSE;
	ULONG64 end = start + size;
	if (end < start) return FALSE;
	ULONG64 pteBase = _IT(Map, Map->System.PteBase);
	for (ULONG64 addr = start; addr < end; addr += 0x1000) {
		ULONG64 pte = ((addr >> 9) & 0x7FFFFFFFF8) + pteBase;
		if (IsKernelPtr((PVOID)pte)) {
			*(ULONG64*)pte = 0;
			__invlpg((PVOID)addr);
		}
	}
	return TRUE;
}

__forceinline BOOLEAN DisablePspNotify(PMap Map, PUCHAR origValue) {
	PUCHAR mask = (PUCHAR)_IT(Map, (ULONG64)Map->Notify.PspNotifyEnableMask);
	if (!mask) return FALSE;
	*origValue = *mask;
	*mask &= 0xF0;
	return TRUE;
}

__forceinline BOOLEAN EnablePspNotify(PMap Map, UCHAR origValue) {
	PUCHAR mask = (PUCHAR)_IT(Map, (ULONG64)Map->Notify.PspNotifyEnableMask);
	if (!mask) return FALSE;
	*mask = origValue;
	return TRUE;
}

__forceinline ProcessContext EnterTargetProcess(PMap Map) {
	ProcessContext ctx;
	ctx.interruptsEnabled = (__readeflags() & 0x200) != 0;
	if (ctx.interruptsEnabled) _disable();
	ctx.oldCr3 = __readcr3();
	__writecr3(Map->Process.CurrentCr3);
	return ctx;
}

__forceinline VOID LeaveTargetProcess(PMap Map, ProcessContext* ctx) {
	__writecr3(ctx->oldCr3);
	if (ctx->interruptsEnabled) _enable();
}

__declspec(noinline) MemAllocTable* NewAllocTable(PMap Map, INT cap) {
	MemAllocTable* t = (MemAllocTable*)_Alloc(Map, sizeof(MemAllocTable), Map->MEMORY_TAG.TlbN);
	if (!t) return NULL;
	__stosb((PUCHAR)t, 0, sizeof(MemAllocTable));
	t->entries = (MemAllocEntry*)_Alloc(Map, sizeof(MemAllocEntry) * cap, Map->MEMORY_TAG.llhS);
	if (!t->entries) {
		_Free(Map, t, Map->MEMORY_TAG.TlbN);
		return NULL;
	}
	__stosb((PUCHAR)t->entries, 0, sizeof(MemAllocEntry) * cap);
	t->capacity = cap;
	return t;
}

__declspec(noinline) VOID FreeAllocTable(PMap Map, MemAllocTable* table, BOOLEAN isProcessActive) {
	if (!table) return;
	if (table->entries) {
		if (isProcessActive) {
			ProcessContext ctx = EnterTargetProcess(Map);
			for (INT i = 0; i < table->capacity; i++) {
				MemAllocEntry* e = &table->entries[i];
				if (!e->inUse || !e->history) continue;
				PageHistory* h = e->history;
				if (h->his) {
					for (INT j = h->cnt - 1; j >= 0; j--) ClearAllocItemPte(&h->his[j]);
				}
				if (e->size) FlushTlbRange(e->address, e->size);
			}
			LeaveTargetProcess(Map, &ctx);
		}
		for (INT i = 0; i < table->capacity; i++) {
			MemAllocEntry* e = &table->entries[i];
			if (!e->inUse || !e->history) continue;
			PageHistory* h = e->history;
			if (h->his) {
				for (INT j = h->cnt - 1; j >= 0; j--) {
					AllocItem* it = &h->his[j];
					if (it->poolAddr && IsKernelPtr(it->poolAddr)) _Free(Map, it->poolAddr, Map->MEMORY_TAG.yKeV);
					it->pPageEntry = NULL;
					it->poolAddr = NULL;
					it->type = 0;
				}
				_Free(Map, h->his, Map->MEMORY_TAG.AlcI);
			}
			_Free(Map, h, Map->MEMORY_TAG.News);
		}
		_Free(Map, table->entries, Map->MEMORY_TAG.llhS);
	}
	_Free(Map, table, Map->MEMORY_TAG.TlbN);
}

__forceinline INT FindAllocEntry(MemAllocTable* table, ULONG64 address) {
	if (!table || !table->entries) return -1;
	for (INT i = 0; i < table->capacity; i++)
		if (table->entries[i].inUse && table->entries[i].address == address) return i;
	return -1;
}

__forceinline INT FindFreeSlot(MemAllocTable* table) {
	for (INT i = 0; i < table->capacity; i++)
		if (!table->entries[i].inUse) return i;
	return -1;
}

__declspec(noinline) BOOLEAN ExpandAllocTable(PMap Map, MemAllocTable* table) {
	INT newCap = table->capacity * 2;
	if (newCap > 4096) newCap = 4096;
	if (newCap <= table->capacity) return FALSE;
	MemAllocEntry* ne = (MemAllocEntry*)_Alloc(Map, sizeof(MemAllocEntry) * newCap, Map->MEMORY_TAG.llhS);
	if (!ne) return FALSE;
	__stosb((PUCHAR)ne, 0, sizeof(MemAllocEntry) * newCap);
	__movsb((PUCHAR)ne, (PUCHAR)table->entries, sizeof(MemAllocEntry) * table->capacity);
	_Free(Map, table->entries, Map->MEMORY_TAG.llhS);
	table->entries = ne;
	table->capacity = newCap;
	return TRUE;
}

__declspec(noinline) BOOLEAN AddAllocEntry(PMap Map, MemAllocTable* table, ULONG64 address, SIZE_T size, PageHistory* history) {
	INT slot = FindFreeSlot(table);
	if (slot < 0) {
		if (!ExpandAllocTable(Map, table)) return FALSE;
		slot = FindFreeSlot(table);
		if (slot < 0) return FALSE;
	}
	table->entries[slot] = { address, size, history, TRUE };
	table->cnt++;
	return TRUE;
}

__forceinline BOOLEAN EnsureAllocTableSlot(PMap Map, MemAllocTable* table) {
	if (FindFreeSlot(table) >= 0) return TRUE;
	return ExpandAllocTable(Map, table);
}

__declspec(noinline) MemAllocTable* GetOrCreateAllocTable(PMap Map) {
	MemAllocTable* t = (MemAllocTable*)_InterlockedCompareExchangePointer((PVOID volatile*)&Map->Memory.AllocTable, NULL, NULL);
	if (t) return t;
	MemAllocTable* fresh = NewAllocTable(Map, 32);
	if (!fresh) return NULL;
	MemAllocTable* old = (MemAllocTable*)_InterlockedCompareExchangePointer((PVOID volatile*)&Map->Memory.AllocTable, fresh, NULL);
	if (old) {
		FreeAllocTable(Map, fresh, FALSE);
		return old;
	}
	return fresh;
}

__declspec(noinline) ULONG64 AllocMemory(PMap Map, PDriverControl Control) {
	SIZE_T size = Control->Size;
	if (!size || !_IT(Map, (ULONG64)Map->Notify.PspNotifyEnableMask)) return 0;
	if (size & 0xFFF) size = (size + 0xFFF) & ~0xFFF;
	if (size > 0x7FFFFFFFFFFF) return 0;

	MemAllocTable* table = GetOrCreateAllocTable(Map);
	if (!table) return 0;

	PageHistory* history = (PageHistory*)NewHistory(Map, 256);
	if (!history) return 0;

	ULONG64 pages = size >> 12;
	ULONG64 ptPages = (pages + 511) >> 9;
	ULONG64 pdPages = (ptPages + 511) >> 9;
	ULONG64 pdptPages = (pdPages + 511) >> 9;
	ULONG64 needCalc = pages + ptPages + pdPages + pdptPages + 8;
	if (needCalc > 0xFFFFFFFF) needCalc = 0xFFFFFFFF;
	ULONG need = (ULONG)needCalc;

	if (!EnsureHistoryCapacity(Map, history, (INT)need)) {
		FreePageHistory(Map, history, FALSE, FALSE);
		return 0;
	}

	PrealloCtx pc = { 0 };
	if (!PreallocFill(Map, &pc, need)) {
		PreallocReleaseAll(Map, &pc);
		FreePageHistory(Map, history, FALSE, FALSE);
		return 0;
	}

	KIRQL oldIrql = RaiseIrql(DISPATCH_LEVEL);
	AcquireSpinLock(&table->lock);

	if (!EnsureAllocTableSlot(Map, table)) {
		ReleaseSpinLock(&table->lock);
		LowerIrql(oldIrql);
		PreallocReleaseAll(Map, &pc);
		FreePageHistory(Map, history, FALSE, FALSE);
		return 0;
	}

	ULONG retry = RandomRetryCount(Map, 10, 20);
	UCHAR origNotify = 0;
	ULONG64 address = 0;
	ProcessContext ctx = EnterTargetProcess(Map);
	DisablePspNotify(Map, &origNotify);

	for (ULONG i = 0; i < retry; i++) {
		ULONG64 start = GetRandomBaseAddress(Map, size);
		if (!start) continue;
		if (IsAddressRangeOverlap(table, start, size)) continue;
		if (MakeR3Memory(Map, start, size, history, &pc)) {
			address = start;
			break;
		}
	}

	EnablePspNotify(Map, origNotify);
	LeaveTargetProcess(Map, &ctx);

	if (address && !AddAllocEntry(Map, table, address, size, history)) {
		ProcessContext ctx2 = EnterTargetProcess(Map);
		for (INT i = history->cnt - 1; i >= 0; i--) ClearAllocItemPte(&history->his[i]);
		FlushTlbRange(address, size);
		LeaveTargetProcess(Map, &ctx2);
		address = 0;
	}

	ReleaseSpinLock(&table->lock);
	LowerIrql(oldIrql);

	PreallocReleaseUnused(Map, &pc);

	if (!address) {
		FreePageHistory(Map, history, FALSE, FALSE);
		return 0;
	}
	return address;
}

__declspec(noinline) NTSTATUS FreeMemory(PMap Map, PDriverControl Control) {
	ULONG64 address = Control->Address;
	if (!address || !_IT(Map, (ULONG64)Map->Notify.PspNotifyEnableMask)) return STATUS_INVALID_PARAMETER;

	MemAllocTable* table = (MemAllocTable*)_InterlockedCompareExchangePointer((PVOID volatile*)&Map->Memory.AllocTable, NULL, NULL);
	if (!table) return STATUS_NOT_FOUND;

	KIRQL oldIrql = RaiseIrql(DISPATCH_LEVEL);
	AcquireSpinLock(&table->lock);

	INT idx = FindAllocEntry(table, address);
	if (idx < 0) {
		ReleaseSpinLock(&table->lock);
		LowerIrql(oldIrql);
		return STATUS_NOT_FOUND;
	}

	MemAllocEntry* pEntry = &table->entries[idx];
	SIZE_T freeSize = pEntry->size ? pEntry->size : Control->Size;
	if (!freeSize || freeSize > 0x7FFFFFFFFFFF) {
		ReleaseSpinLock(&table->lock);
		LowerIrql(oldIrql);
		return STATUS_INVALID_PARAMETER;
	}
	if (freeSize & 0xFFF) freeSize = (freeSize + 0xFFF) & ~0xFFF;

	PageHistory* history = pEntry->history;
	UCHAR origNotify = 0;
	ProcessContext ctx = EnterTargetProcess(Map);
	DisablePspNotify(Map, &origNotify);

	FreeR3Memory(Map, address, freeSize);
	if (history && history->his) {
		for (INT i = history->cnt - 1; i >= 0; i--) ClearAllocItemPte(&history->his[i]);
	}

	EnablePspNotify(Map, origNotify);
	LeaveTargetProcess(Map, &ctx);

	pEntry->inUse = FALSE;
	pEntry->address = 0;
	pEntry->size = 0;
	pEntry->history = NULL;
	table->cnt--;

	ReleaseSpinLock(&table->lock);
	LowerIrql(oldIrql);

	KeSleep(Map, 2);

	if (history) {
		if (history->his) {
			for (INT i = history->cnt - 1; i >= 0; i--) {
				AllocItem* it = &history->his[i];
				if (it->poolAddr && IsKernelPtr(it->poolAddr)) _Free(Map, it->poolAddr, Map->MEMORY_TAG.yKeV);
				it->pPageEntry = NULL;
				it->poolAddr = NULL;
				it->type = 0;
			}
			_Free(Map, history->his, Map->MEMORY_TAG.AlcI);
		}
		_Free(Map, history, Map->MEMORY_TAG.News);
	}
	return STATUS_SUCCESS;
}