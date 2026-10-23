__forceinline PEPROCESS LookupProcessByPidViaLinks(PMap Map, HANDLE ProcessId) {
	PLIST_ENTRY head = (PLIST_ENTRY)_IT(Map, Map->System.PsActiveProcessHead);
	if (!head || !Map->System.ActiveProcessLinksOffset || !Map->System.UniqueProcessIdOffset) return NULL;

	ULONG linksOff = Map->System.ActiveProcessLinksOffset;
	ULONG pidOff = Map->System.UniqueProcessIdOffset;

	for (PLIST_ENTRY cur = head->Flink; cur && cur != head; cur = cur->Flink) {
		PEPROCESS proc = (PEPROCESS)((PUCHAR)cur - linksOff);
		if (*(HANDLE*)((PUCHAR)proc + pidOff) == ProcessId) return proc;
	}

	return NULL;
}

__declspec(noinline) NTSTATUS SetProcess(PMap Map, PDriverControl pControl) {
	Map->Process.CurrentCr3 = 0;
	Map->Process.CurrentPEB = 0;
	Map->Process.CurrentProcess = 0;
	Map->Process.process_base = 0;
	Map->Inject.Inject_Data.ProcessID = 0;

	if (!pControl->ProcessId) return STATUS_UNSUCCESSFUL;

	PEPROCESS Process = LookupProcessByPidViaLinks(Map, (HANDLE)pControl->ProcessId);
	if (!Process) return STATUS_NOT_FOUND;

	Map->Process.process_base = ((ULONG64(*)(PVOID))_IT(Map, Map->ImportTable.PsGetProcessSectionBaseAddress))(Process);
	if (!Map->Process.process_base) return STATUS_NOT_FOUND;

	ULONG64 dirBase = *(PULONG64)((PCHAR)Process + Map->System.EprocessDirBaseOffset) & ~0xFULL;
	Map->Process.CurrentCr3 = dirBase;

	ULONG64 wow64 = ((ULONG64(*)(PVOID))_IT(Map, Map->ImportTable.PsGetProcessWow64Process))(Process);
	Map->Process.CurrentPEB = wow64 ? wow64 : (ULONG64)GetEprocessPeb(Map, Process);

	if (pControl->Type) {
		ULONG64 KernelCr3 = dirbase_from_base_address(Map, (PVOID)Map->Process.process_base);
		if (KernelCr3) Map->Process.CurrentCr3 = KernelCr3;
	}

	Map->Process.CurrentProcess = Process;
	Map->Inject.Inject_Data.ProcessID = pControl->ProcessId;

	return STATUS_SUCCESS;
}

__declspec(noinline) NTSTATUS ProtectProcess(PMap Map, PDriverControl pControl) {
	PEPROCESS Process = LookupProcessByPidViaLinks(Map, (HANDLE)pControl->ProcessId);
	if (!Process) return STATUS_NOT_FOUND;

	if (!Map->System.ProtectionOffset) return STATUS_NOT_FOUND;

	_InterlockedExchange8((PCHAR)((ULONG64)Process + Map->System.ProtectionOffset), pControl->Type ? 0x31 : 0x00);

	return STATUS_SUCCESS;
}