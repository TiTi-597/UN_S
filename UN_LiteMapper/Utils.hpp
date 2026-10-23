#define MiGetVirtualAddressMappedByPte(_PteBase, _Pte) (ULONG64)((LONG_PTR)(((LONG_PTR)(_Pte) - _PteBase) << 25L) >> 16)
#define MiGetSystemPteAddress(_VirtualAddress) (ULONG64*)(((_VirtualAddress >> 9) & 0x7FFFFFFFF8))
#define MiGetPteAddress(PteBase, VirtualAddress) (ULONG64*)(((VirtualAddress >> 9) & 0x7FFFFFFFF8) + PteBase)

typedef struct _KDDEBUGGER_DATA64 {
    UCHAR Header[24];
    UCHAR Reserved1A[56];
    ULONG64 PsActiveProcessHead;
    UCHAR Reserved1B[104];
    ULONG64 MmPfnDatabase;
    UCHAR Reserved2A[472];
    USHORT OffsetKThreadApcProcess;
    UCHAR Reserved2B[8];
    USHORT OffsetEprocessPeb;
    UCHAR Reserved2C[2];
    USHORT OffsetEprocessDirectoryTableBase;
    UCHAR Reserved2D[176];
    ULONG64 PteBase;
} KDDEBUGGER_DATA64;
typedef struct _DUMP_HEADER {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[32];
    PVOID KdDebuggerDataBlock;
} DUMP_HEADER, *PDUMP_HEADER;

typedef struct _Map {
    struct {
        ULONG64 KeDelayExecutionThread;
        ULONG64 ZwClose;
        ULONG64 RtlGenerateClass5Guid;
        ULONG64 ExFreePoolWithTag;
        ULONG64 PsGetProcessWow64Process;
        ULONG64 ExAllocatePoolWithTag;
        ULONG64 PsGetProcessSectionBaseAddress;
        ULONG64 MmCopyVirtualMemory;
        ULONG64 ObOpenObjectByPointer;
        ULONG64 PsProcessType;
        ULONG64 ZwAllocateVirtualMemory;
        ULONG64 ZwProtectVirtualMemory;
        ULONG64 ZwFreeVirtualMemory;
        ULONG64 RtlCreateUserThread;
        ULONG64 ZwWaitForSingleObject;
        ULONG64 IofCompleteRequest;
        ULONG64 ZwQueryVirtualMemory;
        ULONG64 IoReleaseRemoveLockEx;
        ULONG64 PsGetThreadWin32Thread;
        ULONG64 KeInitializeApc;
        ULONG64 KeInsertQueueApc;
        ULONG64 PsCreateSystemThread;
        ULONG64 KeIpiGenericCall;
        ULONG64 PsLookupThreadByThreadId;
        ULONG64 ObfDereferenceObject;
    } ImportTable;

    struct {
        ULONG64 CurrentCr3;
        ULONG64 LastFoundCr3;
        ULONG64 CurrentPEB;
        ULONG64 MmPfnDataBase;
        ULONG64 process_base;
        PVOID CurrentProcess;
    } Process;

    struct {
        ULONG64 Ptes;
        ULONG64 PtesPte;
        ULONG64 PteBase;
        PLDR_DATA_TABLE_ENTRY NtoskrnlLdr;
        ULONG ProtectionOffset;
        ULONG KernelApcDisableOffset;
        ULONG ExitStatusOffset;
        ULONG EprocessDirBaseOffset;
        ULONG EprocessPebOffset;
        ULONG KThreadApcProcessOffset;
        ULONG64 PsActiveProcessHead;
        ULONG ActiveProcessLinksOffset;
        ULONG UniqueProcessIdOffset;
        ULONG64 PhysMemRanges;
        ULONG   PhysMemRangeCount;
    } System;

    struct {
        CHAR threadUseMap[512];
        ULONG64 threadDataBuffer[512];
        ULONG64 threadDataBufferSize[512];
    } Thread;

    struct {
        PUCHAR PspNotifyEnableMask;
    } Notify;

    struct {
        PVOID History;
        PVOID* AllocTable;
    } Memory;

    struct {
        ULONG llhS;
        ULONG yKeV;
        ULONG AlcI;
        ULONG News;
        ULONG TlbN;
        ULONG Nono;
    } MEMORY_TAG;

    struct {
        ULONG64 TargetAddress;
        PVOID Inject_Data[6];
    } Inject;

    struct {
        PDEVICE_OBJECT MouseDeviceObject;
        PVOID MouseDeviceExtension;
        BOOLEAN Initialized;
    } MouseContext;

    struct {
        KSPIN_LOCK Lock;
        struct {
            KAPC Apc;
            PETHREAD Thread;
            PVOID Map;
            volatile LONG Suspended;
            volatile LONG State;
        } Entries[64];
    } Suspend;
}Map, * PMap;