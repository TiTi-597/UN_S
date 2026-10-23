__forceinline ULONG MyRandomEx(ULONG64* state) {
    ULONG64 x = *state;
    if (x == 0) x = __rdtsc() | 1;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return (ULONG)(x & MAXLONG);
}

__forceinline NTSTATUS FillRandom(PMap Map, ULONG64 Address, ULONG64 Size) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID randBuffer = ((decltype(ExAllocatePoolWithTag)*)_IT(Map, Map->ImportTable.ExAllocatePoolWithTag))(NonPagedPool, Size, Map->MEMORY_TAG.yKeV);
    if (!randBuffer) return STATUS_INSUFFICIENT_RESOURCES;
    PUCHAR current = (PUCHAR)randBuffer;
    ULONG64 seed = __rdtsc();
    for (ULONG64 i = 0; i < Size; i++) current[i] = (UCHAR)(MyRandomEx(&seed) & 0xFF);
    DriverControl driverOp = { 0 };
    driverOp.Address = Address;
    driverOp.Buffer = (ULONG64)randBuffer;
    driverOp.Size = Size;
    driverOp.Type = 1;
    status = CopyPhysicalMemory(Map, &driverOp);
    ((decltype(ExFreePoolWithTag)*)_IT(Map, Map->ImportTable.ExFreePoolWithTag))(randBuffer, Map->MEMORY_TAG.yKeV);
    return status;
}

__forceinline NTSTATUS MyWrite(PMap Map, ULONG64 Address, ULONG64 Buff, ULONG64 Size) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DriverControl driverOp = { 0 };
    driverOp.Address = Address;
    driverOp.Buffer = (ULONG64)Buff;
    driverOp.Size = Size;
    driverOp.Type = 1;
    status = CopyPhysicalMemory(Map, &driverOp);
    return status;
}

__forceinline NTSTATUS MyRead(PMap Map, ULONG64 TargetAddress, PVOID OutputBuffer, SIZE_T SizeToRead) {
    DriverControl driverOp = { 0 };
    driverOp.Address = TargetAddress;
    driverOp.Buffer = (ULONG64)OutputBuffer;
    driverOp.Size = SizeToRead;
    driverOp.Type = 0;
    NTSTATUS status = CopyPhysicalMemory(Map, &driverOp);
    return status;
}