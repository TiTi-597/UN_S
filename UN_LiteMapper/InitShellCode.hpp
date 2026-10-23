static __declspec(noinline) NTSTATUS Init(PMap pMap, ULONG64 NT_Base) {
    SPOOF_FUNC;

    auto _ExAllocatePoolWithTag = KLI_FN(NT_Base, ExAllocatePoolWithTag);
    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    auto _RtlCaptureContext = KLI_FN(NT_Base, RtlCaptureContext);
    using fn_t = NTSTATUS(__stdcall*)(PCONTEXT, PKTHREAD, ULONG, ULONG, ULONG, ULONG, PULONG, PVOID);
    fn_t _KeCapturePersistentThreadState = reinterpret_cast<fn_t>(GetFunByExport(NT_Base, "KeCapturePersistentThreadState"));

    if (!_ExAllocatePoolWithTag || !_ExFreePoolWithTag || !_RtlCaptureContext || !_KeCapturePersistentThreadState) return STATUS_DEVICE_NOT_READY;

    ULONG dumpBlockSize = KLI_OBF_CONST(ULONG, (ULONG)1 << 18);
    ULONG kdDataOffset = KLI_OBF_CONST(ULONG, 0x2000 + 0x80);

    PDUMP_HEADER dump = (PDUMP_HEADER)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, dumpBlockSize, pMap->MEMORY_TAG.yKeV);
    if (!dump) return STATUS_INSUFFICIENT_RESOURCES;

    CONTEXT con;
    con.ContextFlags = CONTEXT_FULL;
    KLI_OBFUSCATE_CALL(_RtlCaptureContext)(&con);

    NTSTATUS status = KLI_OBFUSCATE_CALL(_KeCapturePersistentThreadState)(&con, NULL, 0, 0, 0, 0, 0, dump);
    if (!NT_SUCCESS(status)) {
        KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(dump, pMap->MEMORY_TAG.yKeV);
        return status;
    }

    KDDEBUGGER_DATA64 kd;
    __movsq((PULONG64)&kd, (CONST PULONG64)((PCHAR)dump + (SIZE_T)kdDataOffset), sizeof(kd) / sizeof(ULONG64));

    KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(dump, pMap->MEMORY_TAG.yKeV);

    if (!kd.MmPfnDatabase || !kd.PteBase || !kd.OffsetEprocessDirectoryTableBase || !kd.PsActiveProcessHead || !kd.OffsetEprocessPeb || !kd.OffsetKThreadApcProcess) return STATUS_INVALID_PARAMETER;

    ULONG64 itKey = KLI_OBFUSCATE_CALL(GetPMapKey)(pMap);

    pMap->Process.MmPfnDataBase = MBA_XOR(ULONG64, *(PULONG64)kd.MmPfnDatabase, itKey);
    pMap->System.PteBase = MBA_XOR(ULONG64, kd.PteBase, itKey);
    pMap->System.EprocessDirBaseOffset = kd.OffsetEprocessDirectoryTableBase;
    pMap->System.EprocessPebOffset = MBA_XOR(ULONG, (ULONG)kd.OffsetEprocessPeb, itKey);
    pMap->System.KThreadApcProcessOffset = MBA_XOR(ULONG, (ULONG)kd.OffsetKThreadApcProcess, itKey);
    pMap->System.PsActiveProcessHead = MBA_XOR(ULONG64, kd.PsActiveProcessHead, itKey);

    using fn_curproc_t = PEPROCESS(__stdcall*)(VOID);
    using fn_curpid_t = HANDLE(__stdcall*)(VOID);
    fn_curproc_t _PsGetCurrentProcess = reinterpret_cast<fn_curproc_t>(GetFunByExport(NT_Base, "PsGetCurrentProcess"));
    fn_curpid_t _PsGetCurrentProcessId = reinterpret_cast<fn_curpid_t>(GetFunByExport(NT_Base, "PsGetCurrentProcessId"));
    if (!_PsGetCurrentProcess || !_PsGetCurrentProcessId) return STATUS_DEVICE_NOT_READY;

    PEPROCESS curProc = KLI_OBFUSCATE_CALL(_PsGetCurrentProcess)();
    HANDLE curPid = KLI_OBFUSCATE_CALL(_PsGetCurrentProcessId)();

    ULONG64 psActiveHead = MBA_XOR(ULONG64, pMap->System.PsActiveProcessHead, itKey);
    ULONG uniquePidOffset = 0;
    for (ULONG off = 0x40; off + 24 <= 0x1000; off += sizeof(HANDLE)) {
        HANDLE candidatePid = *(HANDLE*)((PUCHAR)curProc + off);
        if (candidatePid != curPid) continue;

        PLIST_ENTRY link = (PLIST_ENTRY)((PUCHAR)curProc + off + sizeof(HANDLE));
        ULONG64 flink = (ULONG64)link->Flink;
        ULONG64 blink = (ULONG64)link->Blink;

        if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;
        if (((PLIST_ENTRY)flink)->Blink != link) continue;

        BOOLEAN found = FALSE;
        PLIST_ENTRY cur = link;
        for (INT step = 0; step < 2000; ++step) {
            cur = cur->Flink;
            if ((ULONG64)cur < 0xFFFF800000000000ULL) break;
            if ((ULONG64)cur == psActiveHead) { found = TRUE; break; }
        }
        if (!found) continue;

        uniquePidOffset = off;
        break;
    }

    if (!uniquePidOffset) return STATUS_NOT_FOUND;

    pMap->System.UniqueProcessIdOffset = uniquePidOffset;
    pMap->System.ActiveProcessLinksOffset = uniquePidOffset + sizeof(HANDLE);

    return STATUS_SUCCESS;
}

static __declspec(noinline) NTSTATUS FindMouseClassDevice(PMap pMap, ULONG64 NT_Base) {
    SPOOF_FUNC;

    ULONG64 _IoDriverObjectType = GetFunByExport(NT_Base, "IoDriverObjectType");
    if (!_IoDriverObjectType) return 0;

    auto driverName = KLI_SCOPED_WSTR("\\Driver\\MouClass");

    UNICODE_STRING uniName;
    KLI_OBFUSCATE_CALL(MyRtlInitUnicodeString)(&uniName, driverName);

    using fn_t = NTSTATUS(__stdcall*)(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID*);
    fn_t _ObReferenceObjectByName = reinterpret_cast<fn_t>(GetFunByExport(NT_Base, "ObReferenceObjectByName"));
    auto _ObfDereferenceObject = KLI_FN(NT_Base, ObfDereferenceObject);

    if (!_ObReferenceObjectByName || !_ObfDereferenceObject) return STATUS_DEVICE_NOT_READY;

    PDRIVER_OBJECT pDriverObject = NULL;
    NTSTATUS status = KLI_OBFUSCATE_CALL(_ObReferenceObjectByName)(&uniName, OBJ_CASE_INSENSITIVE, NULL, 0, *(POBJECT_TYPE*)_IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDriverObject);

    if (!NT_SUCCESS(status)) return status;

    NTSTATUS result = STATUS_NOT_FOUND;
    for (PDEVICE_OBJECT pDeviceObject = pDriverObject->DeviceObject; pDeviceObject; pDeviceObject = pDeviceObject->NextDevice) {
        PVOID deviceExtension = pDeviceObject->DeviceExtension;
        if (deviceExtension) {
            pMap->MouseContext.MouseDeviceObject = pDeviceObject;
            pMap->MouseContext.MouseDeviceExtension = deviceExtension;
            pMap->MouseContext.Initialized = TRUE;
            result = STATUS_SUCCESS;
            break;
        }
    }

    KLI_OBFUSCATE_CALL(_ObfDereferenceObject)(pDriverObject);
    return result;
}

static __declspec(noinline) PBYTE GetPspNotifyEnableMask(ULONG64 NT_Base) {
    SPOOF_FUNC;

    auto _PsSetLoadImageNotifyRoutineEx = KLI_FN(NT_Base, PsSetLoadImageNotifyRoutineEx);
    if (!_PsSetLoadImageNotifyRoutineEx) return 0;

    PUCHAR pFunc = (PUCHAR)_PsSetLoadImageNotifyRoutineEx;
    _mm_prefetch((CHAR CONST*)pFunc, _MM_HINT_T0);

    const UCHAR op_lock = (UCHAR)KLI_OBF_CONST(ULONG, 0xF0);
    const UCHAR op_0f = (UCHAR)KLI_OBF_CONST(ULONG, 0x0F);
    const UCHAR op_83 = (UCHAR)KLI_OBF_CONST(ULONG, 0x83);

    for (ULONG i = 0; i < 512; i++) {
        if (pFunc[i] != op_lock) continue;

        for (ULONG skip = 1; skip <= 3; skip++) {
            if (i + skip + 1 >= 512) break;
            UCHAR modrm = pFunc[i + skip + 1];
            if (((modrm >> 6) & 0x3) != 0 || (modrm & 0x7) != 5) continue;

            ULONG disp_off = i + skip + 2;
            if (disp_off + 4 > 512) break;
            LONG disp32 = *(PLONG)(pFunc + disp_off);

            ULONG instr_len = skip + 1 + 1 + 4;
            if (pFunc[i + 1] == op_0f || pFunc[i + 1] == op_83) instr_len += 1;

            PBYTE result = (PBYTE)((ULONG64)(pFunc + i + instr_len) + disp32);
            if ((ULONG64)result >> 47 == (ULONG64)pFunc >> 47) return result;
        }
    }

    return 0;
}

static __declspec(noinline) ULONG GetKernelApcDisableOffset(ULONG64 NT_Base) {
    SPOOF_FUNC;

    auto _KeEnterCriticalRegion = KLI_FN(NT_Base, KeEnterCriticalRegion);
    if (!_KeEnterCriticalRegion) return 0;

    PUCHAR pFunc = (PUCHAR)_KeEnterCriticalRegion;

    const UCHAR op_66 = (UCHAR)KLI_OBF_CONST(ULONG, 0x66);
    const UCHAR op_ff = (UCHAR)KLI_OBF_CONST(ULONG, 0xFF);
    const UCHAR op_88 = (UCHAR)KLI_OBF_CONST(ULONG, 0x88);
    const UCHAR op_81 = (UCHAR)KLI_OBF_CONST(ULONG, 0x81);
    const UCHAR op_80 = (UCHAR)KLI_OBF_CONST(ULONG, 0x80);

    for (INT i = 0; i + 9 <= 32; i++) {
        if (pFunc[i] == op_66 && pFunc[i + 1] == op_ff && pFunc[i + 2] == op_88) return *(PULONG)(pFunc + i + 3);
        if (pFunc[i] == op_66 && pFunc[i + 1] == op_81 && pFunc[i + 2] == op_80) return *(PULONG)(pFunc + i + 3);
    }

    return 0;
}

static __declspec(noinline) ULONG GetExitStatusOffset(ULONG64 NT_Base) {
    SPOOF_FUNC;

    auto _PsGetProcessExitStatus = KLI_FN(NT_Base, PsGetProcessExitStatus);
    if (!_PsGetProcessExitStatus) return 0;

    PUCHAR pFunc = (PUCHAR)_PsGetProcessExitStatus;

    const UCHAR op_8b = (UCHAR)KLI_OBF_CONST(ULONG, 0x8B);
    const UCHAR op_81 = (UCHAR)KLI_OBF_CONST(ULONG, 0x81);

    ULONG offset = 0;
    for (INT i = 0; i + 6 <= 32; i++) {
        if (pFunc[i] == op_8b && pFunc[i + 1] == op_81) { offset = *(PULONG)(pFunc + i + 2); break; }
    }
    if (!offset) return 0;

    using fn_curproc_t = PEPROCESS(__stdcall*)(VOID);
    using fn_exit_t = NTSTATUS(__stdcall*)(PEPROCESS);
    fn_curproc_t _PsGetCurrentProcess = reinterpret_cast<fn_curproc_t>(GetFunByExport(NT_Base, "PsGetCurrentProcess"));
    if (!_PsGetCurrentProcess) return 0;

    PEPROCESS curProc = KLI_OBFUSCATE_CALL(_PsGetCurrentProcess)();
    if (!curProc) return 0;

    NTSTATUS expected = ((fn_exit_t)_PsGetProcessExitStatus)(curProc);
    if (*(NTSTATUS*)((PUCHAR)curProc + offset) != expected) return 0;

    return offset;
}

static __declspec(noinline) ULONG GetProtectionOffset(ULONG64 NT_Base) {
    SPOOF_FUNC; 

    ULONG64 _PsGetProcessProtection = GetFunByExport(NT_Base, "PsGetProcessProtection");
    if (!_PsGetProcessProtection) return 0;

    PUCHAR pFunc = (PUCHAR)_PsGetProcessProtection;

    const UCHAR op_0f = (UCHAR)KLI_OBF_CONST(ULONG, 0x0F);
    const UCHAR op_b6 = (UCHAR)KLI_OBF_CONST(ULONG, 0xB6);
    const UCHAR op_81 = (UCHAR)KLI_OBF_CONST(ULONG, 0x81);
    const UCHAR op_41 = (UCHAR)KLI_OBF_CONST(ULONG, 0x41);
    const UCHAR op_8a = (UCHAR)KLI_OBF_CONST(ULONG, 0x8A);

    ULONG offset = 0;
    for (INT i = 0; i < 16; i++) {
        if (i + 7 <= 16 && pFunc[i] == op_0f && pFunc[i + 1] == op_b6 && pFunc[i + 2] == op_81) {
            offset = *(PULONG)(pFunc + i + 3); break;
        }
        if (i + 4 <= 16 && pFunc[i] == op_0f && pFunc[i + 1] == op_b6 && pFunc[i + 2] == op_41) {
            offset = (ULONG) * (PUCHAR)(pFunc + i + 3); break;
        }
        if (i + 6 <= 16 && pFunc[i] == op_8a && pFunc[i + 1] == op_81) {
            offset = *(PULONG)(pFunc + i + 2); break;
        }
        if (i + 3 <= 16 && pFunc[i] == op_8a && pFunc[i + 1] == op_41) {
            offset = (ULONG) * (PUCHAR)(pFunc + i + 2); break;
        }
    }
    if (!offset) return 0;

    using fn_curproc_t = PEPROCESS(__stdcall*)(VOID);
    using fn_prot_t = UCHAR(__stdcall*)(PEPROCESS);
    fn_curproc_t _PsGetCurrentProcess = reinterpret_cast<fn_curproc_t>(GetFunByExport(NT_Base, "PsGetCurrentProcess"));
    if (!_PsGetCurrentProcess) return 0;

    PEPROCESS curProc = KLI_OBFUSCATE_CALL(_PsGetCurrentProcess)();
    if (!curProc) return 0;

    UCHAR expected = ((fn_prot_t)_PsGetProcessProtection)(curProc);
    if (*(UCHAR*)((PUCHAR)curProc + offset) != expected) return 0;

    return offset;
}