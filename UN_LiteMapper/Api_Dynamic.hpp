static __declspec(noinline) BOOL GetApiAddress(PMap pMap, ULONG seed, ULONG64 NT_Base) {
    SPOOF_FUNC;

    ULONG64 itKey = KLI_OBFUSCATE_CALL(GetPMapKey)(pMap);

    INT indices[25];
    for (INT i = 0; i < 25; i++) indices[i] = i;
    for (INT i = 24; i > 0; i--) {
        INT j = seed % (i + 1);
        seed = KliProtected::seed::mix(seed, static_cast<uint32_t>(i));
        INT temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    for (INT idx = 0; idx < 25; idx++) {
        INT i = indices[idx];
        switch (i) {
        case 0: pMap->ImportTable.KeDelayExecutionThread = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "KeDelayExecutionThread"), itKey);  break;
        case 1: pMap->ImportTable.ZwClose = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwClose"), itKey);  break;
        case 2: pMap->ImportTable.RtlGenerateClass5Guid = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "RtlGenerateClass5Guid"), itKey);  break;
        case 3: pMap->ImportTable.ExFreePoolWithTag = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ExFreePoolWithTag"), itKey);  break;
        case 4: pMap->ImportTable.PsGetProcessWow64Process = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsGetProcessWow64Process"), itKey);  break;
        case 5: pMap->ImportTable.ExAllocatePoolWithTag = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ExAllocatePoolWithTag"), itKey);  break;
        case 6: pMap->ImportTable.PsGetProcessSectionBaseAddress = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsGetProcessSectionBaseAddress"), itKey);  break;
        case 7: pMap->ImportTable.MmCopyVirtualMemory = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "MmCopyVirtualMemory"), itKey); break;
        case 8: pMap->ImportTable.ObOpenObjectByPointer = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ObOpenObjectByPointer"), itKey); break;
        case 9: pMap->ImportTable.PsProcessType = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsProcessType"), itKey); break;
        case 10: pMap->ImportTable.ZwAllocateVirtualMemory = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwAllocateVirtualMemory"), itKey); break;
        case 11: pMap->ImportTable.ZwProtectVirtualMemory = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwProtectVirtualMemory"), itKey); break;
        case 12: pMap->ImportTable.ZwFreeVirtualMemory = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwFreeVirtualMemory"), itKey); break;
        case 13: pMap->ImportTable.RtlCreateUserThread = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "RtlCreateUserThread"), itKey); break;
        case 14: pMap->ImportTable.ZwWaitForSingleObject = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwWaitForSingleObject"), itKey); break;
        case 15: pMap->ImportTable.IofCompleteRequest = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "IofCompleteRequest"), itKey); break;
        case 16: pMap->ImportTable.ZwQueryVirtualMemory = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ZwQueryVirtualMemory"), itKey); break;
        case 17: pMap->ImportTable.IoReleaseRemoveLockEx = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "IoReleaseRemoveLockEx"), itKey); break;
        case 18: pMap->ImportTable.PsGetThreadWin32Thread = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsGetThreadWin32Thread"), itKey); break;
        case 19: pMap->ImportTable.KeInitializeApc = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "KeInitializeApc"), itKey); break;
        case 20: pMap->ImportTable.KeInsertQueueApc = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "KeInsertQueueApc"), itKey); break;
        case 21: pMap->ImportTable.PsCreateSystemThread = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsCreateSystemThread"), itKey); break;
        case 22: pMap->ImportTable.KeIpiGenericCall = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "KeIpiGenericCall"), itKey); break;
        case 23: pMap->ImportTable.PsLookupThreadByThreadId = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "PsLookupThreadByThreadId"), itKey); break;
        case 24: pMap->ImportTable.ObfDereferenceObject = MBA_XOR(ULONG64, GetFunByExport(NT_Base, "ObfDereferenceObject"), itKey); break;
        }
    }

    return TRUE;
}