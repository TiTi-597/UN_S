typedef struct _MsrIpiContext {
	volatile LONG NextSlot;
	ULONG MaxCpu;
	ULONG MsrAddress;
	ULONG64* Values;
} MsrIpiContext;

__declspec(noinline) ULONG64 MsrIpiCallback(PVOID Context) {
	MsrIpiContext* ctx = (MsrIpiContext*)Context;

	LONG slot = _InterlockedIncrement(&ctx->NextSlot) - 1;
	if ((ULONG)slot >= ctx->MaxCpu) return 0;

	ctx->Values[slot] = __readmsr(ctx->MsrAddress);
	return 1;
}

__declspec(noinline) NTSTATUS CopyMsr(PMap pMap, PDriverControl pControl) {
	if (!pControl->Address || !pControl->Buffer || !pControl->Size) return STATUS_UNSUCCESSFUL;

	INT threadIndex = GetThreadUniqueIndexFromMap(pMap, sizeof(DriverControl) + sizeof(MsrIpiContext) + (ULONG64)pControl->Size * sizeof(UINT64) + 64);
	if (threadIndex == -1) return STATUS_UNSUCCESSFUL;

	PDriverControl pControlNonPaged = (PDriverControl)pMap->Thread.threadDataBuffer[threadIndex];
	*pControlNonPaged = *pControl;

	MsrIpiContext* ctx = (MsrIpiContext*)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl));
	ULONG64* pValuesNonPaged = (ULONG64*)(pMap->Thread.threadDataBuffer[threadIndex] + sizeof(DriverControl) + sizeof(MsrIpiContext));
	__stosb((UCHAR*)pValuesNonPaged, 0, pControl->Size * sizeof(UINT64));

	ctx->NextSlot = 0;
	ctx->MaxCpu = (ULONG)pControl->Size;
	ctx->MsrAddress = (ULONG)pControl->Address;
	ctx->Values = pValuesNonPaged;
	((ULONG64(*)(ULONG64(*)(PVOID), PVOID))_IT(pMap, pMap->ImportTable.KeIpiGenericCall))(MsrIpiCallback, (PVOID)ctx);

	ULONG readCnt = (ULONG)ctx->NextSlot;
	if (readCnt > ctx->MaxCpu) readCnt = ctx->MaxCpu;

	__movsb((UCHAR*)pControlNonPaged->Buffer, (UCHAR*)pValuesNonPaged, (ULONG64)pControl->Size * sizeof(UINT64));
	__stosb((UCHAR*)pValuesNonPaged, 0, (ULONG64)pControl->Size * sizeof(UINT64));
	_InterlockedExchange8(&pMap->Thread.threadUseMap[threadIndex], FALSE);

	return readCnt ? (NTSTATUS)readCnt : STATUS_UNSUCCESSFUL;
}