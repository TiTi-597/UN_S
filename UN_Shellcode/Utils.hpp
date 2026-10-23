#define UN_S_Ping                        0x1000
#define UN_S_SetProcess                  0x2000
#define UN_S_ProtectProcess              0x2001
#define UN_S_Get_ProcessBase             0x2002
#define UN_S_GET_ProcessPeb              0x2003
#define UN_S_GetKernelModuleAddress      0x2004
#define UN_S_CopyGlobalPhysicalMemory    0x3000
#define UN_S_CopyPhysicalMemory          0x3001
#define UN_S_CopyKernelVirtualMemory     0x3002
#define UN_S_CopyVirtualMemory           0x3003
#define UN_S_CopyMsr                     0x3004
#define UN_S_AllocateVirtualMemory       0x4000
#define UN_S_ProtectVirtualMemory        0x4001
#define UN_S_QueryVirtualMemory          0x4002
#define UN_S_FreeVirtualMemory           0x4003
#define UN_S_CreateUserThread            0x4004
#define UN_S_AllocMemory                 0x5000
#define UN_S_FreeMemory                  0x5001
#define UN_S_InjectMouseInput            0x6000
#define UN_S_ASMMouseInput               0x6001
#define UN_S_SearchMemoryInProcessEx     0x7000
#define UN_S_InjectDLL                   0x8000
#define UN_S_ApcInjectDLL                0x8001
#define UN_S_RipInjectDLL                0x8002
#define UN_S_Get_Inject_Data             0x9000
#define UN_S_SuspendThread               0x9100
#define UN_S_ResumeThread                0x9101

typedef struct _DriverControl {
    ULONG64 ProcessId;
    ULONG64 Address;
    ULONG64 Size;
    ULONG64 Buffer;
    ULONG64 Type;
}DriverControl, * PDriverControl;
typedef struct _DriverParameter {
    ULONG64 UNKey;
    ULONG64 Flag;
    ULONG64 Control;
    ULONG64 OutputBuffer;
}DriverParameter, * PDriverParameter;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    short LoadCount;
    short TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

struct HardwarePteX64 {
    union {
        ULONG64 all;
        struct {
            ULONG64 valid : 1;
            ULONG64 write : 1;
            ULONG64 owner : 1;
            ULONG64 write_through : 1;
            ULONG64 cache_disable : 1;
            ULONG64 accessed : 1;
            ULONG64 dirty : 1;
            ULONG64 large_page : 1;
            ULONG64 global : 1;
            ULONG64 copy_on_write : 1;
            ULONG64 prototype : 1;
            ULONG64 reserved0 : 1;
            ULONG64 page_frame_number : 36;
            ULONG64 reserved1 : 4;
            ULONG64 software_ws_index : 11;
            ULONG64 no_execute : 1;
        };
    };
};
struct AllocItem {
    ULONG type;
    HardwarePteX64* pPageEntry;
    PVOID poolAddr;
};
struct PageHistory {
    INT cnt;
    INT capacity;
    AllocItem* his;
};
struct MemAllocEntry {
    ULONG64 address;
    SIZE_T size;
    PageHistory* history;
    BOOLEAN inUse;
};
struct MemAllocTable {
    INT cnt;
    INT capacity;
    MemAllocEntry* entries;
    KSPIN_LOCK lock;
};

typedef struct _Inject_Data {
    ULONG64 ProcessID;
    ULONG64 m_Pe_address;
    ULONG64 m_Pe_Size;
    ULONG64 m_loader_shellcode_address;
    ULONG64 m_loader_shellcode_size;
    ULONG64 InjectionResult;
}Inject_Data, * PInject_Data;

struct _Map;

typedef struct _SUSPEND_ENTRY {
	KAPC Apc;  
	PETHREAD Thread; 
	struct _Map* Map;   
	volatile LONG Suspended; 
	volatile LONG State;
} SUSPEND_ENTRY;

typedef struct _SUSPEND_TABLE {
	KSPIN_LOCK    Lock;
	SUSPEND_ENTRY Entries[64];
} SUSPEND_TABLE;

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
        ULONG PhysMemRangeCount;
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
        MemAllocTable* AllocTable;
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
        Inject_Data Inject_Data;
    } Inject;

    struct {
        PDEVICE_OBJECT MouseDeviceObject;
        PVOID MouseDeviceExtension;
        BOOLEAN Initialized;
    } MouseContext;

    struct {
        SUSPEND_TABLE Table;
    } Suspend;
}Map, * PMap;