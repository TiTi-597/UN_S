__declspec(noinline) NTSTATUS CopyVirtualMemory(PMap Map, PDriverControl Control) {
	ULONG64 Copied = 0;
	if (Control->Type == 1) {
		return ((NTSTATUS(*)(PVOID, ULONG64, PVOID, ULONG64, ULONG64, KPROCESSOR_MODE, PULONG64))_IT(Map, Map->ImportTable.MmCopyVirtualMemory))(
			GetCurrentEprocess(Map),
			Control->Buffer,
			Map->Process.CurrentProcess,
			Control->Address,
			Control->Size,
			KernelMode,
			&Copied
			);
	}
	else {
		return ((NTSTATUS(*)(PVOID, ULONG64, PVOID, ULONG64, ULONG64, KPROCESSOR_MODE, PULONG64))_IT(Map, Map->ImportTable.MmCopyVirtualMemory))(
			Map->Process.CurrentProcess,
			Control->Address,
			GetCurrentEprocess(Map),
			Control->Buffer,
			Control->Size,
			KernelMode,
			&Copied
			);
	}
}