__declspec(noinline) NTSTATUS AllocateVirtualMemory(PMap Map, PDriverControl Control) {
	HANDLE ProcessHandle = 0;

	NTSTATUS Status = ((decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer))
		(Map->Process.CurrentProcess, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType), KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	Status = ((decltype(ZwAllocateVirtualMemory)*)_IT(Map, Map->ImportTable.ZwAllocateVirtualMemory))
		(ProcessHandle, (PVOID*)&Control->Address, 0, (PSIZE_T)&Control->Size, Control->Type, Control->ProcessId);
	((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ProcessHandle);

	return NT_SUCCESS(Status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

__declspec(noinline) NTSTATUS ProtectVirtualMemory(PMap Map, PDriverControl Control) {
	HANDLE ProcessHandle = 0;

	NTSTATUS Status = ((decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer))
		(Map->Process.CurrentProcess, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType), KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	Status = ((NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))_IT(Map, Map->ImportTable.ZwProtectVirtualMemory))
		(ProcessHandle, (PVOID*)&Control->Address, (PSIZE_T)&Control->Size, Control->Type, (PULONG)&Control->ProcessId);
	((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ProcessHandle);

	return NT_SUCCESS(Status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

__declspec(noinline) NTSTATUS QueryVirtualMemory(PMap Map, PDriverControl Control) {
	HANDLE ProcessHandle = 0;
	MEMORY_BASIC_INFORMATION memoryInfo = { 0 };
	SIZE_T returnLength = 0;

	NTSTATUS Status = ((decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer))
		(Map->Process.CurrentProcess, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType), KernelMode, &ProcessHandle);

	if (NT_SUCCESS(Status)) {
		Status = ((decltype(ZwQueryVirtualMemory)*)_IT(Map, Map->ImportTable.ZwQueryVirtualMemory))
			(ProcessHandle, (PVOID)Control->Address, MemoryBasicInformation, &memoryInfo, sizeof(memoryInfo), &returnLength);

		if (NT_SUCCESS(Status)) {
			Control->Buffer = (ULONG64)memoryInfo.BaseAddress;
			Control->ProcessId = (ULONG64)memoryInfo.AllocationProtect;
			Control->Size = (ULONG64)memoryInfo.RegionSize;
			Control->Type = (ULONG64)memoryInfo.Type;
		}
		((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ProcessHandle);
		if (NT_SUCCESS(Status)) return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

__declspec(noinline) NTSTATUS FreeVirtualMemory(PMap Map, PDriverControl Control) {
	HANDLE ProcessHandle = 0;

	NTSTATUS Status = ((decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer))
		(Map->Process.CurrentProcess, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType), KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	Status = ((decltype(ZwFreeVirtualMemory)*)_IT(Map, Map->ImportTable.ZwFreeVirtualMemory))
		(ProcessHandle, (PVOID*)&Control->Address, (PSIZE_T)&Control->Size, Control->Type);
	((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ProcessHandle);

	return NT_SUCCESS(Status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

__declspec(noinline) NTSTATUS CreateUserThread(PMap Map, PDriverControl Control) {
	HANDLE ProcessHandle = 0;

	NTSTATUS Status = ((decltype(ObOpenObjectByPointer)*)_IT(Map, Map->ImportTable.ObOpenObjectByPointer))
		(Map->Process.CurrentProcess, OBJ_KERNEL_HANDLE, 0, PROCESS_ALL_ACCESS, *(POBJECT_TYPE*)_IT(Map, Map->ImportTable.PsProcessType), KernelMode, &ProcessHandle);
	if (!NT_SUCCESS(Status)) return STATUS_UNSUCCESSFUL;

	HANDLE ThreadHandle = 0;
	Status = ((NTSTATUS(*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID))_IT(Map, Map->ImportTable.RtlCreateUserThread))
		(ProcessHandle, 0, 0, 0, 0, 0, (PVOID)Control->Address, (PVOID)Control->Type, &ThreadHandle, 0);

	if (NT_SUCCESS(Status)) {
		LARGE_INTEGER Time;
		Time.QuadPart = -(50LL * 1000 * 10);
		((decltype(ZwWaitForSingleObject)*)_IT(Map, Map->ImportTable.ZwWaitForSingleObject))(ThreadHandle, TRUE, &Time);
		((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ThreadHandle);
	}
	((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(ProcessHandle);

	return NT_SUCCESS(Status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}