static __forceinline ULONG64 DeriveKey(ULONG64 addr) {
    ULONG64 k = addr;
    ULONG64 c1 = MBA_OR(ULONG64, MBA_XOR(ULONG64, k, k >> 32), 1);
    ULONG64 c2 = MBA_OR(ULONG64, MBA_XOR(ULONG64, k, k << 32), 1);
    k = MBA_XOR(ULONG64, k, k >> 12);
    k *= c1;
    k = MBA_XOR(ULONG64, k, k >> 27);
    k *= c2;
    k = MBA_XOR(ULONG64, k, k >> 33);
    return k;
}

static __forceinline ULONG64 GetPMapKey(PMap pMap) {
    ULONG64 tagMix = MBA_OR(ULONG64, (ULONG64)pMap->MEMORY_TAG.llhS, (ULONG64)pMap->MEMORY_TAG.yKeV << 32);
    return KLI_OBFUSCATE_CALL(DeriveKey)(MBA_XOR(ULONG64, (ULONG64)pMap, tagMix));
}

static __forceinline VOID XorDecrypt(PUCHAR data, SIZE_T dataSize, CONST CHAR* key, SIZE_T keyLen) {
    if (!data || !key || keyLen == 0 || dataSize == 0) return;
    for (SIZE_T i = 0; i < dataSize; i++) {
        data[i] = MBA_XOR(UCHAR, data[i], (UCHAR)key[i % keyLen]);
    }
}

static __forceinline VOID GetFastSeed(PLARGE_INTEGER SeedValue) {
    NT_ASSERT(SeedValue != NULL);
    INT regs[4];
    __cpuid(regs, 1);
    ULONG64 cpu_entropy = MBA_OR(ULONG64, static_cast<ULONG64>(regs[0]) << 32, static_cast<ULONG64>(regs[3]));
    SeedValue->QuadPart = static_cast<LONGLONG>(MBA_XOR(ULONG64, cpu_entropy, KliProtected::seed::time_seed()));
}

static __forceinline ULONG GenerateRandomTag() {
    LARGE_INTEGER seedValue;
    KLI_OBFUSCATE_CALL(GetFastSeed)(&seedValue);
    INT regs[4];
    __cpuid(regs, 1);
    ULONG64 tsc = __rdtsc();
    ULONG seed = MBA_XOR(ULONG, MBA_XOR(ULONG, seedValue.LowPart, seedValue.HighPart << 16), MBA_XOR(ULONG, static_cast<ULONG>(regs[0] ^ regs[3]), static_cast<ULONG>(tsc >> 4)));
    ULONG tag = 0;
    for (INT i = 0; i < 4; i++) {
        seed = KliProtected::seed::mix(seed, static_cast<uint32_t>(0xE4 + i));
        ULONG idx = seed % 62;
        CHAR c;
        if (idx < 10) c = '0' + idx;
        else if (idx < 36) c = 'A' + (idx - 10);
        else c = 'a' + (idx - 36);
        tag = MBA_OR(ULONG, tag, ((ULONG)c) << (i * 8));
    }
    return tag;
}

static __forceinline VOID MyRtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    DestinationString->Length = 0;
    DestinationString->MaximumLength = 0;
    DestinationString->Buffer = (PWSTR)SourceString;

    if (SourceString) {
        USHORT length = 0;
        while (SourceString[length] != L'\0' && length < 65535) {
            length++;
        }
        DestinationString->Length = length * sizeof(WCHAR);
        DestinationString->MaximumLength = (length + 1) * sizeof(WCHAR);
    }
}

static __declspec(noinline) ULONG64 LocateVerifierThunk(ULONG64 NT_Base, ULONG SizeOfImage) {
    SPOOF_FUNC;

    if (!NT_Base || SizeOfImage < 0x40) return 0;

    auto needleEnc = KLI_SCOPED_ASTR("RtlGenerateClass5Guid");
    PUCHAR needle = (PUCHAR)(CHAR*)needleEnc;
    CONST SIZE_T needleLen = 22;
    PUCHAR base = (PUCHAR)NT_Base;
    SIZE_T scanEnd = (SIZE_T)SizeOfImage - sizeof(ULONG64);

    for (SIZE_T s = 0; s + needleLen <= SizeOfImage; s++) {
        if (base[s] != needle[0]) continue;
        BOOL match = TRUE;
        for (SIZE_T j = 1; j < needleLen; j++) {
            if (base[s + j] != needle[j]) {
                match = FALSE;
                break;
            }
        }
        if (!match) continue;

        ULONG64 nameVA = (ULONG64)(base + s);

        ULONG64 thunkSlot = 0;
        for (SIZE_T i = 0; i <= scanEnd; i += sizeof(ULONG64)) {
            if (*(ULONG64*)(base + i) == nameVA) {
                thunkSlot = (ULONG64)(base + i);
                break; 
            }
        }
        if (!thunkSlot) {
            for (SIZE_T i = 0; i <= scanEnd; i++) {
                if (*(ULONG64*)(base + i) == nameVA) {
                    thunkSlot = (ULONG64)(base + i);
                    break;
                }
            }
        }
        if (!thunkSlot) continue;

        ULONG64 candidate = *(ULONG64*)(thunkSlot + sizeof(ULONG64));
        if (candidate >= NT_Base && candidate < NT_Base + SizeOfImage) return candidate;
    }

    return 0;
}

static __declspec(noinline) NTSTATUS DeleteDriverFile(ULONG64 NT_Base, PUNICODE_STRING pUsDriverPath) {
    SPOOF_FUNC;

    ULONG64 _IoFileObjectType = GetFunByExport(NT_Base, "IoFileObjectType");
    if (!_IoFileObjectType) return 0;

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;

    InitializeObjectAttributes(&ObjectAttributes, pUsDriverPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0);

    auto _IoCreateFileEx = KLI_FN(NT_Base, IoCreateFileEx);
    if (!_IoCreateFileEx) return STATUS_DEVICE_NOT_READY;

    NTSTATUS Status = KLI_OBFUSCATE_CALL(_IoCreateFileEx)(
        &FileHandle, SYNCHRONIZE | DELETE, &ObjectAttributes, &IoStatusBlock, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0,
        CreateFileTypeNone, nullptr, IO_NO_PARAMETER_CHECKING, nullptr);
    if (!NT_SUCCESS(Status)) return Status;

    PFILE_OBJECT FileObject;
    auto _ObReferenceObjectByHandleWithTag = KLI_FN(NT_Base, ObReferenceObjectByHandleWithTag);
    auto _ObCloseHandle = KLI_FN(NT_Base, ObCloseHandle);
    auto _ObfDereferenceObject = KLI_FN(NT_Base, ObfDereferenceObject);
    auto _MmFlushImageSection = KLI_FN(NT_Base, MmFlushImageSection);

    if (!_ObReferenceObjectByHandleWithTag || !_ObCloseHandle) {
        if (_ObCloseHandle) KLI_OBFUSCATE_CALL(_ObCloseHandle)(FileHandle, KernelMode);
        return STATUS_DEVICE_NOT_READY;
    }

    Status = KLI_OBFUSCATE_CALL(_ObReferenceObjectByHandleWithTag)(FileHandle, SYNCHRONIZE | DELETE,
        *(POBJECT_TYPE*)_IoFileObjectType, KernelMode, 0, reinterpret_cast<PVOID*>(&FileObject), nullptr);
    if (!NT_SUCCESS(Status)) {
        KLI_OBFUSCATE_CALL(_ObCloseHandle)(FileHandle, KernelMode);
        return Status;
    }

    PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
    if (!SectionObjectPointer) {
        if (_ObfDereferenceObject) KLI_OBFUSCATE_CALL(_ObfDereferenceObject)(FileObject);
        KLI_OBFUSCATE_CALL(_ObCloseHandle)(FileHandle, KernelMode);
        return STATUS_NOT_FOUND;
    }
    SectionObjectPointer->ImageSectionObject = nullptr;

    BOOLEAN ImageSectionFlushed = _MmFlushImageSection ? KLI_OBFUSCATE_CALL(_MmFlushImageSection)(SectionObjectPointer, MmFlushForDelete) : FALSE;

    if (_ObfDereferenceObject) KLI_OBFUSCATE_CALL(_ObfDereferenceObject)(FileObject);
    KLI_OBFUSCATE_CALL(_ObCloseHandle)(FileHandle, KernelMode);

    if (ImageSectionFlushed) {
        auto _ZwDeleteFile = KLI_FN(NT_Base, ZwDeleteFile);
        if (_ZwDeleteFile) {
            Status = KLI_OBFUSCATE_CALL(_ZwDeleteFile)(&ObjectAttributes);
            if (NT_SUCCESS(Status)) return Status;
        }
    }

    return Status;
}