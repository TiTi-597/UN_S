#define SUSPEND_TABLE_MAX 64
#define SUSPEND_POLL_MS   (-10000)

__forceinline VOID DerefThread(PMap Map, PETHREAD Thread) {
	if (Thread) ((VOID(*)(PVOID))_IT(Map, Map->ImportTable.ObfDereferenceObject))(Thread);
}

__declspec(noinline) VOID SuspendKernelRoutine(struct _KAPC* Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
	(Apc);
	(NormalRoutine);
	(NormalContext); 
	(SystemArgument1); 
	(SystemArgument2);
}

__declspec(noinline) VOID SuspendRundownRoutine(struct _KAPC* Apc) {
	SUSPEND_ENTRY* entry = (SUSPEND_ENTRY*)((PUCHAR)Apc - FIELD_OFFSET(SUSPEND_ENTRY, Apc));
	PMap Map = entry->Map;
	PETHREAD Thread = entry->Thread;
	SUSPEND_TABLE* table = &Map->Suspend.Table;

	BOOLEAN reclaimed = FALSE;
	AcquireSpinLock(&table->Lock);
	if (entry->State == 1 || entry->State == 2) {
		entry->Suspended = 0;
		entry->State = 0;
		entry->Thread = NULL;
		reclaimed = TRUE;
	}
	ReleaseSpinLock(&table->Lock);

	if (reclaimed && Thread) DerefThread(Map, Thread);
}

__declspec(noinline) VOID SuspendNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	(SystemArgument1); (SystemArgument2);
	SUSPEND_ENTRY* entry = (SUSPEND_ENTRY*)NormalContext;
	PMap Map = entry->Map;
	SUSPEND_TABLE* table = &Map->Suspend.Table;

	LARGE_INTEGER interval;
	interval.QuadPart = SUSPEND_POLL_MS;
	while (entry->Suspended) ((NTSTATUS(*)(KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER))_IT(Map, Map->ImportTable.KeDelayExecutionThread))(KernelMode, FALSE, &interval);

	AcquireSpinLock(&table->Lock);
	PETHREAD thread = entry->Thread;
	entry->Thread = NULL;
	entry->State = 0;
	ReleaseSpinLock(&table->Lock);

	DerefThread(Map, thread);
}

__declspec(noinline) NTSTATUS SuspendThread(PMap Map, PDriverControl pControl) {
	if (!pControl->ProcessId) return STATUS_INVALID_PARAMETER;

	SUSPEND_TABLE* table = &Map->Suspend.Table;

	PETHREAD thread = NULL;
	NTSTATUS status = ((NTSTATUS(*)(HANDLE, PETHREAD*))_IT(Map, Map->ImportTable.PsLookupThreadByThreadId))((HANDLE)pControl->ProcessId, &thread);
	if (!NT_SUCCESS(status)) return status;

	AcquireSpinLock(&table->Lock);

	for (INT i = 0; i < SUSPEND_TABLE_MAX; i++) {
		if (table->Entries[i].Thread == thread) {
			LONG st = table->Entries[i].State;
			ReleaseSpinLock(&table->Lock);
			DerefThread(Map, thread);
			if (st == 2) return STATUS_DEVICE_BUSY;
			return STATUS_SUCCESS;
		}
	}

	SUSPEND_ENTRY* entry = NULL;
	for (INT i = 0; i < SUSPEND_TABLE_MAX; i++) {
		if (table->Entries[i].State == 0) { 
			entry = &table->Entries[i];
			break;
		}
	}
	if (!entry) {
		ReleaseSpinLock(&table->Lock);
		DerefThread(Map, thread);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	entry->Thread = thread;
	entry->Map = Map;
	entry->Suspended = 1;
	entry->State = 1;

	((VOID(*)(PRKAPC, PRKTHREAD, ULONG, PKKERNEL_ROUTINE, PKRUNDOWN_ROUTINE, PKNORMAL_ROUTINE, KPROCESSOR_MODE, PVOID))
		_IT(Map, Map->ImportTable.KeInitializeApc))(&entry->Apc, (PRKTHREAD)thread, OriginalApcEnvironment, SuspendKernelRoutine, SuspendRundownRoutine, SuspendNormalRoutine, KernelMode, entry);

	ReleaseSpinLock(&table->Lock);

	BOOLEAN inserted = ((BOOLEAN(*)(PRKAPC, PVOID, PVOID, KPRIORITY))_IT(Map, Map->ImportTable.KeInsertQueueApc))(&entry->Apc, NULL, NULL, IO_NO_INCREMENT);
	if (!inserted) {
		AcquireSpinLock(&table->Lock);
		BOOLEAN rollback = (entry->State == 1);
		if (rollback) {
			entry->Suspended = 0;
			entry->State = 0;
			entry->Thread = NULL;
		}
		ReleaseSpinLock(&table->Lock);
		if (rollback) DerefThread(Map, thread);
		return STATUS_THREAD_IS_TERMINATING;
	}

	return STATUS_SUCCESS;
}

__declspec(noinline) NTSTATUS ResumeThread(PMap Map, PDriverControl pControl) {
	if (!pControl->ProcessId) return STATUS_INVALID_PARAMETER;

	SUSPEND_TABLE* table = &Map->Suspend.Table;

	PETHREAD thread = NULL;
	NTSTATUS status = ((NTSTATUS(*)(HANDLE, PETHREAD*))_IT(Map, Map->ImportTable.PsLookupThreadByThreadId))((HANDLE)pControl->ProcessId, &thread);
	if (!NT_SUCCESS(status)) return status;

	AcquireSpinLock(&table->Lock);
	NTSTATUS result = STATUS_NOT_FOUND;
	for (INT i = 0; i < SUSPEND_TABLE_MAX; i++) {
		if (table->Entries[i].Thread == thread && table->Entries[i].State == 1) {
			table->Entries[i].Suspended = 0;
			table->Entries[i].State = 2;
			result = STATUS_SUCCESS;
			break;
		}
	}
	ReleaseSpinLock(&table->Lock);

	DerefThread(Map, thread);
	return result;
}