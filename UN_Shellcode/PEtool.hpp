__forceinline BOOLEAN GetImageDosHead(PMap Map, PVOID dll, SIZE_T dllSize, PIMAGE_DOS_HEADER* DosHead) {
	if (!dll || dllSize < sizeof(IMAGE_DOS_HEADER) || !DosHead) return FALSE;
	if (!MyMmIsAddressValid(Map, dll)) return FALSE;

	PIMAGE_DOS_HEADER p = (PIMAGE_DOS_HEADER)dll;
	if (p->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
	*DosHead = p;
	return TRUE;
}

__forceinline BOOLEAN GetImageNtHead(PMap Map, PVOID dll, SIZE_T dllSize, PIMAGE_DOS_HEADER DosHead, PIMAGE_NT_HEADERS* NtHread) {
	if (!dll || !DosHead || !NtHread) return FALSE;
	if (!MyMmIsAddressValid(Map, dll)) return FALSE;

	LONG e_lfanew = DosHead->e_lfanew;
	if (e_lfanew <= 0) return FALSE;
	if ((ULONG64)e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dllSize) return FALSE;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG64)dll + e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
	if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) return FALSE;
	if ((nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) return FALSE;
	if (nt->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)) return FALSE;

	USHORT numSections = nt->FileHeader.NumberOfSections;
	if (numSections == 0) return FALSE;
	ULONG64 sectionsEnd = (ULONG64)e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (ULONG64)numSections * sizeof(IMAGE_SECTION_HEADER);
	if (sectionsEnd > dllSize) return FALSE;

	*NtHread = nt;
	return TRUE;
}

__forceinline PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS NtHread) {
	return (PIMAGE_SECTION_HEADER)((ULONG64)NtHread + sizeof(IMAGE_NT_HEADERS64));
}

__forceinline SIZE_T GetPeSize(_In_ PIMAGE_NT_HEADERS NtHread, _In_ PIMAGE_SECTION_HEADER SectionHeader, _In_ ULONG nAlign) {
	if (nAlign == 0) return 0;
	ULONG64 ImageSize = ((ULONG64)NtHread->OptionalHeader.SizeOfHeaders + nAlign - 1) / nAlign * nAlign;
	for (USHORT i = 0; i < NtHread->FileHeader.NumberOfSections; ++i) {
		ULONG64 CodeSize = SectionHeader[i].Misc.VirtualSize;
		ULONG64 LoadSize = SectionHeader[i].SizeOfRawData;
		ULONG64 MaxSize = (LoadSize > CodeSize) ? LoadSize : CodeSize;
		ULONG64 SectionSize = ((ULONG64)SectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
		if (ImageSize < SectionSize) ImageSize = SectionSize;
	}
	return (SIZE_T)ImageSize;
}

__declspec(noinline) BOOLEAN CopySection(PMap Map, PVOID dll, SIZE_T dllSize, PIMAGE_NT_HEADERS NtHread, PIMAGE_SECTION_HEADER SectionHeader, VOID* MemoryAddress) {
	if (!MemoryAddress || !dll) return FALSE;

	ULONG HeaderSize = NtHread->OptionalHeader.SizeOfHeaders;
	if (HeaderSize == 0 || HeaderSize > dllSize) return FALSE;

	__movsb((PUCHAR)MemoryAddress, (PUCHAR)dll, HeaderSize);

	USHORT numSections = NtHread->FileHeader.NumberOfSections;
	for (USHORT i = 0; i < numSections; ++i) {
		ULONG va = SectionHeader[i].VirtualAddress;
		ULONG raw = SectionHeader[i].SizeOfRawData;
		ULONG ptr = SectionHeader[i].PointerToRawData;
		if (va == 0 || raw == 0) continue;
		if ((ULONG64)ptr + raw > dllSize) return FALSE;

		__movsb((PUCHAR)MemoryAddress + va, (PUCHAR)dll + ptr, raw);
	}
	return TRUE;
}

__declspec(noinline) VOID FixLocData(PIMAGE_NT_HEADERS NtHread, VOID* MemoryAddress) {
	ULONG relocRva = NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	ULONG relocSize = NtHread->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (relocRva == 0 || relocSize < sizeof(IMAGE_BASE_RELOCATION)) return;

	ULONG64 Delta = (ULONG64)MemoryAddress - NtHread->OptionalHeader.ImageBase;
	if (Delta == 0) return;

	PUCHAR base = (PUCHAR)MemoryAddress;
	PUCHAR relocBegin = base + relocRva;
	PUCHAR relocEnd = relocBegin + relocSize;

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)relocBegin;
	while ((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION) <= relocEnd) {
		ULONG block = pLoc->SizeOfBlock;
		if (block < sizeof(IMAGE_BASE_RELOCATION)) break;
		if ((PUCHAR)pLoc + block > relocEnd) break;
		if (pLoc->VirtualAddress == 0 && block == 0) break;

		ULONG entries = (block - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		USHORT* pLocData = (USHORT*)((PUCHAR)pLoc + sizeof(IMAGE_BASE_RELOCATION));
		for (ULONG i = 0; i < entries; i++) {
			USHORT type = pLocData[i] >> 12;
			USHORT off = pLocData[i] & 0x0FFF;
			if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
				ULONG64* pAddress = (ULONG64*)(base + pLoc->VirtualAddress + off);
				*pAddress += Delta;
			}
		}
		pLoc = (PIMAGE_BASE_RELOCATION)((PUCHAR)pLoc + block);
	}
}