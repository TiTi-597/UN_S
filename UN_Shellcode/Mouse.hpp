typedef struct _MOUSE_INPUT_DATA {
	USHORT UnitId;
	USHORT Flags;
	union {
		ULONG Buttons;
		struct {
			USHORT ButtonFlags;
			USHORT ButtonData;
		};
	};
	ULONG RawButtons;
	LONG LastX;
	LONG LastY;
	ULONG ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

#define MOUCLASS_DEVEXT_SPINLOCK         0x90
#define MOUCLASS_DEVEXT_PENDING_IRP      0x98

EXTERN_C VOID MouseClassServiceCallback(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed, ULONG64 KeAcquireSpinLockAtDpcLevel, ULONG64 KeReleaseSpinLockFromDpcLevel, ULONG64 IofCompleteRequest, ULONG64 IoReleaseRemoveLockEx, ULONG64 memmove);

__declspec(noinline) NTSTATUS InjectMouseInput(PMap Map, PDriverControl Control) {
	if (!Control->Buffer) return STATUS_INVALID_PARAMETER;
	if (!Map->MouseContext.Initialized || !Map->MouseContext.MouseDeviceExtension) return STATUS_DEVICE_NOT_READY;

	PUCHAR devExt = (PUCHAR)Map->MouseContext.MouseDeviceExtension;
	PKSPIN_LOCK spinLock = (PKSPIN_LOCK)(devExt + MOUCLASS_DEVEXT_SPINLOCK);
	KIRQL oldIrql = RaiseIrql(DISPATCH_LEVEL);
	AcquireSpinLock(spinLock);

	PLIST_ENTRY pendingQueue = (PLIST_ENTRY)(devExt + MOUCLASS_DEVEXT_PENDING_IRP);

	if (pendingQueue->Flink == pendingQueue) {
		ReleaseSpinLock(spinLock);
		LowerIrql(oldIrql);
		return STATUS_NOT_FOUND;
	}

	PLIST_ENTRY entry = pendingQueue->Flink;
	PLIST_ENTRY nextEntry = entry->Flink;
	pendingQueue->Flink = nextEntry;
	nextEntry->Blink = pendingQueue;

	PIRP pendingIrp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

	PDRIVER_CANCEL oldCancelRoutine = (PDRIVER_CANCEL)_InterlockedExchangePointer((PVOID volatile*)&pendingIrp->CancelRoutine, NULL);

	if (oldCancelRoutine == NULL) {
		if (pendingIrp->Cancel) {
			ReleaseSpinLock(spinLock);
			LowerIrql(oldIrql);
			pendingIrp->IoStatus.Status = STATUS_CANCELLED;
			pendingIrp->IoStatus.Information = 0;
			((decltype(IofCompleteRequest)*)_IT(Map, Map->ImportTable.IofCompleteRequest))(pendingIrp, IO_MOUSE_INCREMENT);
			return STATUS_CANCELLED;
		}
		entry->Flink = pendingQueue->Flink;
		entry->Blink = pendingQueue;
		pendingQueue->Flink->Blink = entry;
		pendingQueue->Flink = entry;
		ReleaseSpinLock(spinLock);
		LowerIrql(oldIrql);
		return STATUS_CANCELLED;
	}

	PIO_STACK_LOCATION irpStack = pendingIrp->Tail.Overlay.CurrentStackLocation;
	ULONG bufferSize = irpStack->Parameters.Read.Length;

	ULONG bytesToCopy = sizeof(MOUSE_INPUT_DATA);
	if (bytesToCopy > bufferSize) bytesToCopy = bufferSize;

	PVOID irpBuffer = pendingIrp->AssociatedIrp.SystemBuffer;

	ReleaseSpinLock(spinLock);
	LowerIrql(oldIrql);

	if (irpBuffer && bytesToCopy >= sizeof(MOUSE_INPUT_DATA)) {
		__movsb((UCHAR*)irpBuffer, (UCHAR*)Control->Buffer, sizeof(MOUSE_INPUT_DATA));
		pendingIrp->IoStatus.Status = STATUS_SUCCESS;
		pendingIrp->IoStatus.Information = bytesToCopy;
	}
	else {
		pendingIrp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		pendingIrp->IoStatus.Information = 0;
	}

	((decltype(IofCompleteRequest)*)_IT(Map, Map->ImportTable.IofCompleteRequest))(pendingIrp, IO_MOUSE_INCREMENT);

	return STATUS_SUCCESS;
}

__forceinline PVOID CustomMemmove(PVOID dest, PVOID src, SIZE_T count) {
	if (dest == src || count == 0) return dest;

	ULONG_PTR d = (ULONG_PTR)dest;
	ULONG_PTR s = (ULONG_PTR)src;

	if (d > s && d < s + count) {
		PUCHAR pd = (PUCHAR)dest + count - 1;
		PUCHAR ps = (PUCHAR)src + count - 1;
		while (count--) {
			*pd-- = *ps--;
		}
	}
	else {
		__movsb((PUCHAR)dest, (PUCHAR)src, count);
	}

	return dest;
}

EXTERN_C __declspec(noinline) NTSTATUS ASMMouseInput(PMap Map, PDriverControl Control) {
	if (!Control->Buffer) return STATUS_INVALID_PARAMETER;
	if (!Map->MouseContext.Initialized || !Map->MouseContext.MouseDeviceObject) return STATUS_DEVICE_NOT_READY;

	MOUSE_INPUT_DATA MouseData = *(MOUSE_INPUT_DATA*)Control->Buffer;
	ULONG Consumed = 0;

	KIRQL oldIrql = RaiseIrql(DISPATCH_LEVEL);

	MouseClassServiceCallback(
		Map->MouseContext.MouseDeviceObject, &MouseData, &MouseData + 1, &Consumed,
		(ULONG64)AcquireSpinLock, (ULONG64)ReleaseSpinLock, _IT(Map, Map->ImportTable.IofCompleteRequest),
		_IT(Map, Map->ImportTable.IoReleaseRemoveLockEx), (ULONG64)CustomMemmove);

	LowerIrql(oldIrql);

	if (Consumed) return STATUS_SUCCESS;
	return STATUS_UNSUCCESSFUL;
}