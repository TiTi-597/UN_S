typedef struct _PEB_LDR_DATA32 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _PEB_LDR_DATA64 {
    ULONG Length;
    BOOLEAN Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;
typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD Reserved3[2];
    DWORD Ldr;
} PEB32, * PPEB32;
typedef struct _PEB64 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    DWORD64 Reserved3[2];
    DWORD64 Ldr;
} PEB64, * PPEB64;
typedef struct _STRING32 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONG  Buffer;
} STRING32;
typedef struct _STRING64 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONG64  Buffer;
} STRING64;
typedef struct _LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    STRING32 FullDllName;
    STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    union {
        LIST_ENTRY64 InInitializationOrderLinks;
        LIST_ENTRY64 InProgressLinks;
    };
    DWORD64 DllBase;
    DWORD64 EntryPoint;
    ULONG SizeOfImage;
    STRING64 FullDllName;
    STRING64 BaseDllName;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

__declspec(noinline) ULONG64 GetModuleAddress(ULONG_PTR Key, CONST CHAR* ModuleName, INT Type, BOOL Is64Bit) {
    if (!ModuleName) return 0;

    ULONG64 PEB = GetProcessEnvironmentBlock(Key);
    if (!PEB) return 0;

    WCHAR* wModuleName = nullptr;
    if (ModuleName != nullptr) {
        INT numChars = LI_FN(MultiByteToWideChar)(CP_ACP, 0, ModuleName, -1, nullptr, 0);
        if (numChars) {
            wModuleName = (WCHAR*)SecureAlloc(numChars * sizeof(WCHAR));
            if (wModuleName && LI_FN(MultiByteToWideChar)(CP_ACP, 0, ModuleName, -1, wModuleName, numChars) == 0) {
                SecureFree(wModuleName);
                wModuleName = nullptr;
            }
        }
    }
    if (!wModuleName) return 0;

    typedef NTSTATUS(*MemoryOpFunc)(ULONG_PTR, ULONG64, PBYTE, INT, INT);
    MemoryOpFunc MemoryOperation = NULL;

    switch (Type) {
    case 0:
        MemoryOperation = (MemoryOpFunc)OperateProcessMemory;
        break;
    case 1:
        MemoryOperation = (MemoryOpFunc)OperateVirtualMemory;
        break;
    default:
        SecureFree(wModuleName);
        return 0;
    }

    if (!MemoryOperation) {
        SecureFree(wModuleName);
        return 0;
    }

    ULONG64 result = 0;

    if (Is64Bit) {
        LocalPtr<PPEB64> Peb(sizeof(PEB64));
        LocalPtr<PPEB_LDR_DATA64> Ldr(sizeof(PEB_LDR_DATA64));

        MemoryOperation(Key, PEB, (PBYTE)&Peb, sizeof(PEB64), 0);
        MemoryOperation(Key, (&Peb)->Ldr, (PBYTE)&Ldr, sizeof(PEB_LDR_DATA64), 0);

        for (INT64 pCur = (&Ldr)->InMemoryOrderModuleList.Flink;
            pCur != (&Peb)->Ldr + offsetof(PEB_LDR_DATA64, InMemoryOrderModuleList);) {

            LocalPtr<PLDR_DATA_TABLE_ENTRY64> curData(sizeof(LDR_DATA_TABLE_ENTRY64));
            MemoryOperation(Key, pCur, (PBYTE)&curData, sizeof(LDR_DATA_TABLE_ENTRY64), 0);

            PLDR_DATA_TABLE_ENTRY64 LdrDataEntry = CONTAINING_RECORD(&curData, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
            pCur = LdrDataEntry->InMemoryOrderLinks.Flink;

            if (LdrDataEntry->BaseDllName.Buffer) {
                LocalPtr<wchar_t*> wszBuff(520);
                MemoryOperation(Key, LdrDataEntry->BaseDllName.Buffer, (PBYTE)&wszBuff, LdrDataEntry->BaseDllName.Length + 2, 0);

                if (!LI_FN(_wcsicmp)(wModuleName, &wszBuff)) {
                    result = LdrDataEntry->DllBase;
                    break;
                }
            }
        }
    }
    else {
        LocalPtr<PPEB32> Peb(sizeof(PEB32));
        LocalPtr<PPEB_LDR_DATA32> Ldr(sizeof(PEB_LDR_DATA32));

        MemoryOperation(Key, PEB, (PBYTE)&Peb, sizeof(PEB32), 0);
        MemoryOperation(Key, (&Peb)->Ldr, (PBYTE)&Ldr, sizeof(PEB_LDR_DATA32), 0);

        for (INT pCur = (&Ldr)->InMemoryOrderModuleList.Flink;
            pCur != (&Peb)->Ldr + offsetof(PEB_LDR_DATA32, InMemoryOrderModuleList);) {

            LocalPtr<PLDR_DATA_TABLE_ENTRY32> curData(sizeof(LDR_DATA_TABLE_ENTRY32));
            MemoryOperation(Key, pCur, (PBYTE)&curData, sizeof(LDR_DATA_TABLE_ENTRY32), 0);

            PLDR_DATA_TABLE_ENTRY32 LdrDataEntry = CONTAINING_RECORD(&curData, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
            pCur = LdrDataEntry->InMemoryOrderLinks.Flink;

            if (LdrDataEntry->BaseDllName.Buffer) {
                LocalPtr<wchar_t*> wszBuff(520);
                MemoryOperation(Key, LdrDataEntry->BaseDllName.Buffer, (PBYTE)&wszBuff, LdrDataEntry->BaseDllName.Length + 2, 0);

                if (!LI_FN(_wcsicmp)(wModuleName, &wszBuff)) {
                    result = LdrDataEntry->DllBase;
                    break;
                }
            }
        }
    }

    SecureFree(wModuleName);
    return result;
}

__declspec(noinline) ULONG64 GetFunctionAddress(ULONG_PTR Key, ULONG64 ModuleBase, CONST CHAR* FunctionName, INT Type) {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_EXPORT_DIRECTORY exportDir;

    PULONG addressOfNames;
    PUSHORT addressOfNameOrdinals;
    PULONG addressOfFunctions;

    ULONG64 functionAddress = 0;

    if (ModuleBase == 0 || !FunctionName) return 0;

    typedef NTSTATUS(*MemoryOpFunc)(ULONG_PTR, ULONG64, PBYTE, INT, INT);
    MemoryOpFunc MemoryOperation = NULL;

    switch (Type) {
    case 0:
        MemoryOperation = (MemoryOpFunc)OperateProcessMemory;
        break;
    case 1:
        MemoryOperation = (MemoryOpFunc)OperateVirtualMemory;
        break;
    default:
        return 0;
    }

    if (!MemoryOperation) return 0;

    if (!MemoryOperation(Key, ModuleBase, (PBYTE)&dosHeader, sizeof(dosHeader), 0)) return 0;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < sizeof(IMAGE_DOS_HEADER) || dosHeader.e_lfanew > 0x1000) return 0;
    if (!MemoryOperation(Key, ModuleBase + dosHeader.e_lfanew, (PBYTE)&ntHeaders, sizeof(IMAGE_NT_HEADERS64), 0)) return 0;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return 0;
    if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;

    ULONG exportRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportRVA == 0 || exportSize == 0 || exportRVA >= ntHeaders.OptionalHeader.SizeOfImage) return 0;
    if (!MemoryOperation(Key, ModuleBase + exportRVA, (PBYTE)&exportDir, sizeof(exportDir), 0)) return 0;
    if (exportDir.NumberOfFunctions == 0 || exportDir.NumberOfNames == 0 || exportDir.NumberOfFunctions > 0x10000 || exportDir.NumberOfNames > 0x10000) return 0;

    ULONG namesToRead = min(exportDir.NumberOfNames, 2048);
    ULONG namesArraySize = namesToRead * sizeof(ULONG);
    ULONG ordinalsArraySize = namesToRead * sizeof(USHORT);

    addressOfNames = (PULONG)LI_FN(HeapAlloc).forwarded()(LI_FN(GetProcessHeap).in(LI_MODULE("KERNEL32.dll").get())(), 0, namesArraySize);
    addressOfNameOrdinals = (PUSHORT)LI_FN(HeapAlloc).forwarded()(LI_FN(GetProcessHeap).in(LI_MODULE("KERNEL32.dll").get())(), 0, ordinalsArraySize);

    if (!addressOfNames || !addressOfNameOrdinals) {
        if (addressOfNames) LI_FN(HeapFree).forwarded()(LI_FN(GetProcessHeap).in(LI_MODULE("KERNEL32.dll").get())(), 0, addressOfNames);
        if (addressOfNameOrdinals) LI_FN(HeapFree).forwarded()(LI_FN(GetProcessHeap).in(LI_MODULE("KERNEL32.dll").get())(), 0, addressOfNameOrdinals);
        return 0;
    }

    ULONG64 addressOfNamesAddr = ModuleBase + exportDir.AddressOfNames;
    ULONG64 addressOfNameOrdinalsAddr = ModuleBase + exportDir.AddressOfNameOrdinals;

    if (!MemoryOperation(Key, addressOfNamesAddr, (PBYTE)addressOfNames, namesArraySize, 0)) {
        const ULONG CHUNK_SIZE = 1024;
        ULONG totalRead = 0;
        BOOL readSuccess = TRUE;

        while (totalRead < namesArraySize && readSuccess) {
            ULONG toRead = min(CHUNK_SIZE, namesArraySize - totalRead);

            if (!MemoryOperation(Key, addressOfNamesAddr + totalRead, (PBYTE)addressOfNames + totalRead, toRead, 0)) {
                toRead = 256;
                if (totalRead + toRead > namesArraySize) toRead = namesArraySize - totalRead;

                if (!MemoryOperation(Key, addressOfNamesAddr + totalRead, (PBYTE)addressOfNames + totalRead, toRead, 0)) {
                    readSuccess = FALSE;
                    break;
                }
            }
            totalRead += toRead;
        }

        if (!readSuccess) goto cleanup;
    }

    if (!MemoryOperation(Key, addressOfNameOrdinalsAddr, (PBYTE)addressOfNameOrdinals, ordinalsArraySize, 0)) {
        const ULONG CHUNK_SIZE = 1024;
        ULONG totalRead = 0;
        BOOL readSuccess = TRUE;

        while (totalRead < ordinalsArraySize && readSuccess) {
            ULONG toRead = min(CHUNK_SIZE, ordinalsArraySize - totalRead);

            if (!MemoryOperation(Key, addressOfNameOrdinalsAddr + totalRead, (PBYTE)addressOfNameOrdinals + totalRead, toRead, 0)) {
                toRead = 256;
                if (totalRead + toRead > ordinalsArraySize) toRead = ordinalsArraySize - totalRead;

                if (!MemoryOperation(Key, addressOfNameOrdinalsAddr + totalRead, (PBYTE)addressOfNameOrdinals + totalRead, toRead, 0)) {
                    readSuccess = FALSE;
                    break;
                }
            }
            totalRead += toRead;
        }

        if (!readSuccess) goto cleanup;
    }

    for (ULONG i = 0; i < namesToRead; i++) {
        USHORT ordIndex = addressOfNameOrdinals[i];
        if (ordIndex >= exportDir.NumberOfFunctions) continue;

        ULONG nameRVA = addressOfNames[i];
        if (nameRVA == 0 || nameRVA >= ntHeaders.OptionalHeader.SizeOfImage) continue;

        CHAR functionNameBuffer[128];
        if (!MemoryOperation(Key, ModuleBase + nameRVA, (PBYTE)functionNameBuffer, sizeof(functionNameBuffer) - 1, 0)) continue;

        functionNameBuffer[sizeof(functionNameBuffer) - 1] = '\0';

        if (my_strcmp(functionNameBuffer, FunctionName) == 0) {
            ULONG functionsToRead = min(exportDir.NumberOfFunctions, ordIndex + 1);
            ULONG functionsArraySize = functionsToRead * sizeof(ULONG);
            addressOfFunctions = (PULONG)LI_FN(HeapAlloc).forwarded()(LI_FN(GetProcessHeap).in(LI_MODULE("KERNEL32.dll").get())(), 0, functionsArraySize);
            if (!addressOfFunctions) break;

            ULONG64 addressOfFunctionsAddr = ModuleBase + exportDir.AddressOfFunctions;
            if (MemoryOperation(Key, addressOfFunctionsAddr, (PBYTE)addressOfFunctions, functionsArraySize, 0)) {
                ULONG funcRVA = addressOfFunctions[ordIndex];

                if (funcRVA != 0 && funcRVA < ntHeaders.OptionalHeader.SizeOfImage && !(funcRVA >= exportRVA && funcRVA < exportRVA + exportSize)) {
                    functionAddress = ModuleBase + funcRVA;
                }
            }
            else {
                const ULONG CHUNK_SIZE = 1024;
                ULONG totalRead = 0;
                BOOL readSuccess = TRUE;

                while (totalRead < functionsArraySize && readSuccess) {
                    ULONG toRead = min(CHUNK_SIZE, functionsArraySize - totalRead);

                    if (!MemoryOperation(Key, addressOfFunctionsAddr + totalRead, (PBYTE)addressOfFunctions + totalRead, toRead, 0)) {
                        toRead = 256;
                        if (totalRead + toRead > functionsArraySize) toRead = functionsArraySize - totalRead;
                        if (!MemoryOperation(Key, addressOfFunctionsAddr + totalRead, (PBYTE)addressOfFunctions + totalRead, toRead, 0)) {
                            readSuccess = FALSE;
                            break;
                        }
                    }
                    totalRead += toRead;
                }

                if (readSuccess) {
                    ULONG funcRVA = addressOfFunctions[ordIndex];
                    if (funcRVA != 0 && funcRVA < ntHeaders.OptionalHeader.SizeOfImage && !(funcRVA >= exportRVA && funcRVA < exportRVA + exportSize)) {
                        functionAddress = ModuleBase + funcRVA;
                    }
                }
            }

            LI_FN(HeapFree).forwarded()(LI_FN(GetProcessHeap).forwarded()(), 0, addressOfFunctions);
            break;
        }
    }

cleanup:
    if (addressOfNames)LI_FN(HeapFree).forwarded()(LI_FN(GetProcessHeap).forwarded()(), 0, addressOfNames);
    if (addressOfNameOrdinals) LI_FN(HeapFree).forwarded()(LI_FN(GetProcessHeap).forwarded()(), 0, addressOfNameOrdinals);

    return functionAddress;
}