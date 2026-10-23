__declspec(noinline) ULONG64 GetKernelModuleAddress(PMap Map, PDriverControl pControl) {
	PLDR_DATA_TABLE_ENTRY ntosLdr = (PLDR_DATA_TABLE_ENTRY)_IT(Map, (ULONG64)Map->System.NtoskrnlLdr);
	PLDR_DATA_TABLE_ENTRY pCurEntry = ntosLdr;
	wchar_t* substr = (wchar_t*)pControl->Buffer;

	do {
		if (pCurEntry->BaseDllName.Buffer == NULL || ((ULONG64)pCurEntry->BaseDllName.Buffer >> 63) == 0) {
			pCurEntry = (PLDR_DATA_TABLE_ENTRY)pCurEntry->InLoadOrderLinks.Flink;
			continue;
		}

		wchar_t* p1 = pCurEntry->BaseDllName.Buffer;
		wchar_t* p2 = substr;
		BOOLEAN found = FALSE;
		while (*p1 != L'\0') {
			if (*p1 == *p2) {
				wchar_t* t1 = p1;
				wchar_t* t2 = p2;
				while (*t1 != L'\0' && *t2 != L'\0' && *t1 == *t2) {
					t1++; t2++;
				}
				if (*t2 == L'\0') {
					found = TRUE;
					break;
				}
			}
			p1++;
		}
		if (found) return (ULONG64)pCurEntry->DllBase;

		pCurEntry = (PLDR_DATA_TABLE_ENTRY)pCurEntry->InLoadOrderLinks.Flink;
	} while (pCurEntry != ntosLdr);

	return 0;
}

__declspec(noinline) NTSTATUS CopyKernelVirtualMemory(PMap Map, PDriverControl Control) {
    if (!MyMmIsAddressValid(Map, (PVOID)Control->Address)) return STATUS_UNSUCCESSFUL;
    if (Control->Type == 1) __movsb((PUCHAR)Control->Address, (PUCHAR)Control->Buffer, Control->Size);
    else __movsb((PUCHAR)Control->Buffer, (PUCHAR)Control->Address, Control->Size);

    return STATUS_SUCCESS;
}