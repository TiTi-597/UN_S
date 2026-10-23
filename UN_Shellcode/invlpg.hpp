#define INVLPG_SLOT_COUNT 2
#define INVLPG_MAX_COPY_SIZE (32ULL * 1024 * 1024)

typedef struct {
	ULONG64 PageOffset;
	ULONG64 RemainSize;

	ULONG64 SlotPage[INVLPG_SLOT_COUNT];
	ULONG64* SlotPagePte[INVLPG_SLOT_COUNT];
	ULONG64 SlotOriginalPte[INVLPG_SLOT_COUNT];
	ULONG64 SlotCurrentPhys[INVLPG_SLOT_COUNT];
	UCHAR SlotLruAge[INVLPG_SLOT_COUNT];
	UCHAR NextSlotHint;

	ULONG64 CachedVa1G;
	ULONG64 CachedPdpte;
	ULONG64 CachedPdpteAddress;
	ULONG64 CachedVa2M;
	ULONG64 CachedPde;
	ULONG64 CachedPdeAddress;
	BOOLEAN Cache1GValid;
	BOOLEAN Cache2MValid;
} InvlpgCopyMemoryParameters;

namespace MemOperateType {
	enum {
		Read = 0,
		Write = 1,
		ForceWrite = 2,
	};
}

__forceinline INT GetThreadUniqueIndexFromMap(PMap Map, ULONG64 BufferSize) {
	if (BufferSize < PAGE_SIZE) BufferSize = PAGE_SIZE;

	INT threadIndex = -1;

	for (INT i = 0; i < 512; ++i) {
		if (!_InterlockedCompareExchange8(&Map->Thread.threadUseMap[i], TRUE, FALSE)) {
			threadIndex = i;
			break;
		}
	}

	if (threadIndex != -1) {
		if (Map->Thread.threadDataBufferSize[threadIndex] < BufferSize || !Map->Thread.threadDataBuffer[threadIndex]) {
			if (Map->Thread.threadDataBuffer[threadIndex]) {
				((VOID(*)(ULONG64, ULONG))_IT(Map, Map->ImportTable.ExFreePoolWithTag))(Map->Thread.threadDataBuffer[threadIndex], Map->MEMORY_TAG.Nono);
				Map->Thread.threadDataBuffer[threadIndex] = 0;
				Map->Thread.threadDataBufferSize[threadIndex] = 0;
			}

			Map->Thread.threadDataBuffer[threadIndex] =
				((ULONG64(*)(POOL_TYPE, SIZE_T, ULONG))_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPoolNx, BufferSize, Map->MEMORY_TAG.Nono);
			if (Map->Thread.threadDataBuffer[threadIndex]) {
				Map->Thread.threadDataBufferSize[threadIndex] = BufferSize;
			}
			else {
				Map->Thread.threadDataBufferSize[threadIndex] = 0;
				_InterlockedExchange8(&Map->Thread.threadUseMap[threadIndex], 0);
				threadIndex = -1;
			}
		}
	}

	return threadIndex;
}

__forceinline VOID InvlpgInitSlots(InvlpgCopyMemoryParameters* Parameters, ULONG64 PtesBase, ULONG64 PtesPteBase, INT threadIndex) {
	INT phase = (INT)(__rdtsc() & 1);

	INT slotIndex[INVLPG_SLOT_COUNT];
	slotIndex[0] = threadIndex + (phase ? 512 : 0);
	slotIndex[1] = threadIndex + (phase ? 0 : 512);

	for (INT i = 0; i < INVLPG_SLOT_COUNT; ++i) {
		Parameters->SlotPage[i] = PtesBase + slotIndex[i] * PAGE_SIZE;
		Parameters->SlotPagePte[i] = (ULONG64*)PtesPteBase + slotIndex[i];
		Parameters->SlotOriginalPte[i] = *Parameters->SlotPagePte[i];
		Parameters->SlotCurrentPhys[i] = ~0ULL;
		Parameters->SlotLruAge[i] = 0;
	}
	Parameters->NextSlotHint = (UCHAR)phase;
	Parameters->Cache1GValid = FALSE;
	Parameters->Cache2MValid = FALSE;
}

__forceinline VOID InvlpgCleanupSlots(InvlpgCopyMemoryParameters* Parameters) {
	for (INT i = 0; i < INVLPG_SLOT_COUNT; ++i) {
		*Parameters->SlotPagePte[i] = Parameters->SlotOriginalPte[i];
		__invlpg((VOID*)Parameters->SlotPage[i]);
	}
}

__forceinline INT InvlpgAcquireSlot(InvlpgCopyMemoryParameters* Parameters, ULONG64 PhysPageBase, ULONG64 PtePermBits) {
	if (!PhysPageBase || (PhysPageBase >> 52)) return -1;

	INT hit = -1;
	INT lru = 0;
	UCHAR maxAge = 0;

	for (INT i = 0; i < INVLPG_SLOT_COUNT; ++i) {
		if (Parameters->SlotCurrentPhys[i] == PhysPageBase) {
			hit = i;
		}
		if (Parameters->SlotLruAge[i] >= maxAge) {
			maxAge = Parameters->SlotLruAge[i];
			lru = i;
		}
	}

	INT idx;
	if (hit >= 0) {
		idx = hit;
	}
	else {
		idx = lru;
		if (Parameters->NextSlotHint < INVLPG_SLOT_COUNT && Parameters->SlotCurrentPhys[Parameters->NextSlotHint] == ~0ULL) idx = Parameters->NextSlotHint;

		ULONG64 NewPte = PhysPageBase | PtePermBits;
		if (*(Parameters->SlotPagePte[idx]) != NewPte) {
			*(Parameters->SlotPagePte[idx]) = NewPte;
			__invlpg((VOID*)Parameters->SlotPage[idx]);
		}
		Parameters->SlotCurrentPhys[idx] = PhysPageBase;
		Parameters->NextSlotHint = (UCHAR)((idx + 1) % INVLPG_SLOT_COUNT);
	}

	for (INT i = 0; i < INVLPG_SLOT_COUNT; ++i) Parameters->SlotLruAge[i] = (i == idx) ? 0 : (UCHAR)(Parameters->SlotLruAge[i] + 1);

	return idx;
}

__forceinline ULONG64 InvlpgReadPte(InvlpgCopyMemoryParameters* Parameters, ULONG64 PhysAddress) {
	INT idx = InvlpgAcquireSlot(Parameters, PhysAddress & ~0xFFFULL, 0x103 & (~(1 << 9)));
	if (idx < 0) return 0;
	return *(volatile ULONG64*)(Parameters->SlotPage[idx] + (PhysAddress & 0xFFF));
}

__declspec(noinline) BOOLEAN InvlpgCopyPhysicalAddress(InvlpgCopyMemoryParameters* Parameters, ULONG64 Address, PVOID Buffer, ULONG64 Size, ULONG64 Write) {
	ULONG64 PermBits = (Write == MemOperateType::ForceWrite ? 0x1EB : 0x103) & (~(1 << 9));
	INT idx = InvlpgAcquireSlot(Parameters, Address & ~0xFFFULL, PermBits);
	if (idx < 0) return FALSE;

	UCHAR* Target = (UCHAR*)(Parameters->SlotPage[idx] + (Address & 0xFFF));
	if (!Buffer) return FALSE;

	if (!Write) __movsb((UCHAR*)Buffer, Target, Size);
	else __movsb(Target, (UCHAR*)Buffer, Size);
	return TRUE;
}

__declspec(noinline) ULONG64 TranslateLinearAddress(InvlpgCopyMemoryParameters* Parameters, ULONG64 Cr3, ULONG64 VirtualAddress, ULONG64* PxeAddress) {
	ULONG64 va_1g = VirtualAddress >> 30;
	ULONG64 va_2m = VirtualAddress >> 21;

	ULONG64 pdpte = 0;
	ULONG64 pdpte_address = 0;
	ULONG64 pde = 0;
	ULONG64 pde_address = 0;

	if (Parameters->Cache2MValid && Parameters->CachedVa2M == va_2m) {
		pde = Parameters->CachedPde;
		pde_address = Parameters->CachedPdeAddress;
	}
	else {
		if (Parameters->Cache1GValid && Parameters->CachedVa1G == va_1g) {
			pdpte = Parameters->CachedPdpte;
			pdpte_address = Parameters->CachedPdpteAddress;
		}
		else {
			ULONG64 pml4_address = (Cr3 & 0xFFFFFFFFFF000) + 8 * ((VirtualAddress >> 39) & 0x1FF);
			ULONG64 pml4 = InvlpgReadPte(Parameters, pml4_address);
			if (!(pml4 & 1)) return 0;
			if (((pml4 >> 12) & 0xFFFFFFFFFF) == ((Cr3 >> 12) & 0xFFFFFFFFFF)) return 0;

			pdpte_address = (pml4 & 0xFFFFFFFFFF000) + 8 * ((VirtualAddress >> 30) & 0x1FF);
			pdpte = InvlpgReadPte(Parameters, pdpte_address);
			if (!(pdpte & 1)) return 0;

			Parameters->CachedVa1G = va_1g;
			Parameters->CachedPdpte = pdpte;
			Parameters->CachedPdpteAddress = pdpte_address;
			Parameters->Cache1GValid = TRUE;
		}

		if ((pdpte >> 7) & 1) {
			if (!(pdpte & 0b10)) *PxeAddress = pdpte_address;
			return (pdpte & 0xFFFFFC0000000) + (VirtualAddress & 0x3FFFFFFF);
		}

		pde_address = (pdpte & 0xFFFFFFFFFF000) + 8 * ((VirtualAddress >> 21) & 0x1FF);
		pde = InvlpgReadPte(Parameters, pde_address);
		if (!(pde & 1)) return 0;

		Parameters->CachedVa2M = va_2m;
		Parameters->CachedPde = pde;
		Parameters->CachedPdeAddress = pde_address;
		Parameters->Cache2MValid = TRUE;
	}

	if ((pde >> 7) & 1) {
		if (!(pde & 0b10)) *PxeAddress = pde_address;
		return (pde & 0xFFFFFFFE00000) + (VirtualAddress & 0x1FFFFF);
	}

	ULONG64 pte_address = (pde & 0xFFFFFFFFFF000) + 8 * ((VirtualAddress >> 12) & 0x1FF);
	ULONG64 pte = InvlpgReadPte(Parameters, pte_address);
	if (!(pte & 1)) return 0;
	if (!(pte & 0b10)) *PxeAddress = pte_address;
	if (pte & 0x200000000000) return (pte & 0xFFFFFFFF000) + (VirtualAddress & 0xFFF);

	return (pte & 0xFFFFFFFFFF000) + (VirtualAddress & 0xFFF);
}

__declspec(noinline) NTSTATUS CopyPhysicalMemory(PMap pMap, PDriverControl pControl) {
	if (!pControl->Address || !pControl->Buffer || !pControl->Size || !pMap->Process.CurrentCr3) return STATUS_UNSUCCESSFUL;
	if (pControl->Size > INVLPG_MAX_COPY_SIZE) return STATUS_INVALID_PARAMETER;

	INT threadIndex = GetThreadUniqueIndexFromMap(pMap, pControl->Size + sizeof(DriverControl) + sizeof(InvlpgCopyMemoryParameters) + 64);
	if (threadIndex == -1) return STATUS_UNSUCCESSFUL;

	PDriverControl pControlNonPaged = (PDriverControl)pMap->Thread.threadDataBuffer[threadIndex];
	*pControlNonPaged = *pControl;

	if (!pControlNonPaged->Buffer) {
		_InterlockedExchange8(&pMap->Thread.threadUseMap[threadIndex], FALSE);
		return STATUS_UNSUCCESSFUL;
	}

	InvlpgCopyMemoryParameters* pParametersNonPaged = (InvlpgCopyMemoryParameters*)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl));
	ULONG64 pBufferNonPaged = (ULONG64)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl) + sizeof(InvlpgCopyMemoryParameters));

	InvlpgInitSlots(pParametersNonPaged, _IT(pMap, pMap->System.Ptes), _IT(pMap, pMap->System.PtesPte), threadIndex);
	pParametersNonPaged->PageOffset = 0;
	pParametersNonPaged->RemainSize = pControlNonPaged->Size;

	if (pControlNonPaged->Type) __movsb((UCHAR*)pBufferNonPaged, (UCHAR*)pControlNonPaged->Buffer, pControlNonPaged->Size);

	_disable();
	KIRQL kirql = RaiseIrql(DISPATCH_LEVEL);

	ULONG64 Cr3 = pMap->Process.CurrentCr3;

	while (TRUE) {
		if (pParametersNonPaged->RemainSize <= 0) break;

		ULONG64 PxeAddress = 0;
		ULONG64 PhysicalAddress = TranslateLinearAddress(pParametersNonPaged, Cr3, pControlNonPaged->Address + pParametersNonPaged->PageOffset, &PxeAddress);
		if (!PhysicalAddress) break;

		if (PxeAddress && (pControlNonPaged->Type == MemOperateType::Write)) break;

		ULONG64 BytesToCopy = min(PAGE_SIZE - (PhysicalAddress & 0xFFF), pParametersNonPaged->RemainSize);
		if (!BytesToCopy) break;

		if (!InvlpgCopyPhysicalAddress(pParametersNonPaged, PhysicalAddress, (PVOID)(pBufferNonPaged + pParametersNonPaged->PageOffset), BytesToCopy, pControlNonPaged->Type)) break;

		pParametersNonPaged->RemainSize -= BytesToCopy;
		pParametersNonPaged->PageOffset += BytesToCopy;
	}

	InvlpgCleanupSlots(pParametersNonPaged);

	LowerIrql(kirql);
	_enable();

	if (pControlNonPaged->Type == MemOperateType::Read) {
		ULONG64 completed = pControlNonPaged->Size - pParametersNonPaged->RemainSize;
		if (completed) __movsb((UCHAR*)pControlNonPaged->Buffer, (UCHAR*)pBufferNonPaged, completed);
		__stosb((UCHAR*)pBufferNonPaged, 0, pControlNonPaged->Size);
	}
	_InterlockedExchange8(&pMap->Thread.threadUseMap[threadIndex], FALSE);

	ULONG64 remain = pParametersNonPaged->RemainSize;
	if (remain == 0) return STATUS_SUCCESS;
	if (remain == pControlNonPaged->Size) return STATUS_UNSUCCESSFUL;
	return STATUS_PARTIAL_COPY;
}

__declspec(noinline) NTSTATUS CopyGlobalPhysicalMemory(PMap pMap, PDriverControl pControl) {
	if (!pControl->Address || !pControl->Buffer || !pControl->Size) return STATUS_UNSUCCESSFUL;
	if (pControl->Size > INVLPG_MAX_COPY_SIZE) return STATUS_INVALID_PARAMETER;

	INT threadIndex = GetThreadUniqueIndexFromMap(pMap, pControl->Size + sizeof(DriverControl) + sizeof(InvlpgCopyMemoryParameters) + 64);
	if (threadIndex == -1) return STATUS_UNSUCCESSFUL;

	PDriverControl pControlNonPaged = (PDriverControl)pMap->Thread.threadDataBuffer[threadIndex];
	*pControlNonPaged = *pControl;

	if (!pControlNonPaged->Buffer) {
		_InterlockedExchange8(&pMap->Thread.threadUseMap[threadIndex], FALSE);
		return STATUS_UNSUCCESSFUL;
	}

	InvlpgCopyMemoryParameters* pParametersNonPaged = (InvlpgCopyMemoryParameters*)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl));
	ULONG64 pBufferNonPaged = (ULONG64)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl) + sizeof(InvlpgCopyMemoryParameters));

	InvlpgInitSlots(pParametersNonPaged, _IT(pMap, pMap->System.Ptes), _IT(pMap, pMap->System.PtesPte), threadIndex);
	pParametersNonPaged->PageOffset = 0;
	pParametersNonPaged->RemainSize = pControlNonPaged->Size;

	if (pControlNonPaged->Type) __movsb((UCHAR*)pBufferNonPaged, (UCHAR*)pControlNonPaged->Buffer, pControlNonPaged->Size);

	_disable();
	KIRQL kirql = RaiseIrql(DISPATCH_LEVEL);

	ULONG64 PhysicalAddress = (ULONG64)pControlNonPaged->Address;

	while (TRUE) {
		if (pParametersNonPaged->RemainSize <= 0) break;
		ULONG64 CurrentPhysical = PhysicalAddress + pParametersNonPaged->PageOffset;
		ULONG64 BytesToCopy = min(PAGE_SIZE - (CurrentPhysical & 0xFFF), pParametersNonPaged->RemainSize);
		if (!BytesToCopy) break;
		if (!InvlpgCopyPhysicalAddress(pParametersNonPaged, CurrentPhysical, (PVOID)(pBufferNonPaged + pParametersNonPaged->PageOffset), BytesToCopy, pControlNonPaged->Type)) break;

		pParametersNonPaged->RemainSize -= BytesToCopy;
		pParametersNonPaged->PageOffset += BytesToCopy;
	}

	InvlpgCleanupSlots(pParametersNonPaged);

	LowerIrql(kirql);
	_enable();

	if (pControlNonPaged->Type == 0) {
		ULONG64 completed = pControlNonPaged->Size - pParametersNonPaged->RemainSize;
		if (completed) __movsb((UCHAR*)pControlNonPaged->Buffer, (UCHAR*)pBufferNonPaged, completed);
		__stosb((UCHAR*)pBufferNonPaged, 0, pControlNonPaged->Size);
	}
	_InterlockedExchange8(&pMap->Thread.threadUseMap[threadIndex], FALSE);

	ULONG64 remain = pParametersNonPaged->RemainSize;
	if (remain == 0) return STATUS_SUCCESS;
	if (remain == pControlNonPaged->Size) return STATUS_UNSUCCESSFUL;
	return STATUS_PARTIAL_COPY;
}