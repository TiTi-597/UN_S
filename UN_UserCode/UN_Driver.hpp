#define UN_MAGICNUMBER 'UNS'

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

__declspec(noinline) ULONG_PTR GetXorKey() {
    ULONG_PTR peb = (ULONG_PTR)NtCurrentTeb()->ProcessEnvironmentBlock;

#ifdef _WIN64
    ULONG_PTR imageBase = *(ULONG_PTR*)(peb + 0x10);
#else
    ULONG_PTR imageBase = *(ULONG_PTR*)(peb + 0x08);
#endif

    DWORD e_lfanew = ((IMAGE_DOS_HEADER*)imageBase)->e_lfanew;
    DWORD timeDateStamp = ((IMAGE_NT_HEADERS*)(imageBase + e_lfanew))->FileHeader.TimeDateStamp;

    ULONG_PTR key = imageBase ^ peb ^ timeDateStamp;

    ULONG_PTR width = sizeof(ULONG_PTR) * 8;
    ULONG_PTR m1 = imageBase | 1;
    ULONG_PTR m2 = peb | 1;

    key = (key * m1) ^ (key >> (peb & (width - 1)));
    key = (key * m2) ^ (key >> (imageBase & (width - 1)));
    key = (key * m1) ^ (key >> (timeDateStamp & (width - 1)));

    return key;
}

__declspec(noinline) ULONG64 InitAppKey(CONST CHAR* Key, ULONG_PTR* AppKey) {
    LoadAndImportDlls();
    if (!IsRunningAsAdmin()) return StatusCode::NoUAC;

    _Globals* Globals = (_Globals*)(SecureAlloc(sizeof(_Globals)));
    if (!Globals) return StatusCode::NoSecretKeyPointer;

    if (!Key) {
        SecureFree(Globals);
        return StatusCode::NoSecretKeyPointer;
    }
    else if (LI_FN(lstrlenA)(Key) != 32) {
        SecureFree(Globals);
        return StatusCode::MismatchSecretKeyLength;
    }
    __movsb((PBYTE)&Globals->SecretKey, (PBYTE)Key, 33);

    PCHAR MachineCode = NULL;
    if (!GetMachineCode(MachineCode)) {
        SecureFree(Globals);
        return StatusCode::InvalidResponse;
    }
    __movsb((PBYTE)&Globals->hwid, (PBYTE)MachineCode, 18);
    SecureFree(MachineCode);

    LocalPtr<CHAR*> request(MAX_PATH);
    LI_FN(sprintf)(&request, xorstr_("UN_AUTH*%s"), Key);

    CHAR* pipapi_response = NULL;
    INT pipapi_response_size = 0;
    if (!tcpRequest(xorstr_(""), 0, &request, &pipapi_response, &pipapi_response_size)) {
        SecureFree(Globals);
        return StatusCode::ConnectionFailed;
    }

    ULONG64 result = Verify_ParseResponse(pipapi_response);
    SecureFree(pipapi_response);

    if (result == StatusCode::Success) {
        Globals->source = (ULONG_PTR)NtCurrentTeb()->ProcessEnvironmentBlock;
        *AppKey = (ULONG_PTR)Globals ^ GetXorKey();
    }
    else {
        SecureFree(Globals);
    }

    return result;
}

__declspec(noinline) ULONG64 PreVerifySecretKeyForProduct(_Globals* Globals) {
    LocalPtr<CHAR*> request(MAX_PATH);
    LI_FN(sprintf)(&request, xorstr_("UN_PRODUCT*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    CHAR* pipapi_response = NULL;
    INT pipapi_response_size = 0;
    if (!tcpRequest(xorstr_(""), 0, &request, &pipapi_response, &pipapi_response_size)) return StatusCode::ConnectionFailed;

    ULONG64 result = Verify_ParseResponse(pipapi_response);
    SecureFree(pipapi_response);

    if (result == StatusCode::Success) Globals->RegSetValueExA = (ULONG64)LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(xorstr_("ADVAPI32.dll")), xorstr_("RegSetValueExA"));

    return result;
}

__declspec(noinline) BOOL GetVerifyCode(_Globals* Globals) {
    DriverParameter parameter;
    ULONG64 outputbuffer;

    parameter.Flag = UN_S_Ping;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer >= '0000' && outputbuffer <= 'zzzz';
}

__declspec(noinline) ULONG64 RequestShellcodeFromServer(_Globals* Globals, CHAR** outShellcode, INT* outSize) {
    CHAR* request = (CHAR*)SecureAlloc(MAX_PATH);
    if (!request) return StatusCode::MemoryAllocFailed;
    LI_FN(sprintf)(request, xorstr_("UN_SHELLCODE*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    CHAR* response = NULL;
    INT responseSize = 0;
    if (!tcpRequest(xorstr_(""), 0, request, &response, &responseSize)) {
        SecureFree(request);
        if (response) SecureFree(response);
        return StatusCode::ShellcodeRequestFailed;
    }
    SecureFree(request);

    if (!verifyDataSource(response, xorstr_(""))) {
        SecureFree(response);
        return StatusCode::ShellcodeVerifyFailed;
    }

    *outShellcode = response + 8;
    *outSize = responseSize - 8;
    return StatusCode::Success;
}

__declspec(noinline) ULONG64 RequestMapperToTempFile(_Globals* Globals, BOOL Type, CHAR** outDriverPath) {
    CHAR* request = (CHAR*)SecureAlloc(MAX_PATH);
    if (!request) return StatusCode::MemoryAllocFailed;
    LI_FN(sprintf)(request, Type ? xorstr_("UN_MAPPER_X*%s*%s*%s") : xorstr_("UN_MAPPER*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    CHAR* mapper_response = NULL;
    INT mapper_response_size = 0;
    if (!tcpRequest(xorstr_(""), 0, request, &mapper_response, &mapper_response_size)) {
        SecureFree(request);
        if (mapper_response) SecureFree(mapper_response);
        return StatusCode::MapperRequestFailed;
    }
    if (!verifyDataSource(mapper_response, xorstr_(""))) {
        SecureFree(request);
        SecureFree(mapper_response);
        return StatusCode::DataSourceVerifyFailed;
    }
    SecureFree(request);

    CHAR* driverName = GenerateRandomString(8);
    if (!driverName) {
        SecureFree(mapper_response);
        return StatusCode::MemoryAllocFailed;
    }

    CHAR* tempPath = (CHAR*)SecureAlloc(MAX_PATH);
    if (!tempPath) {
        SecureFree(mapper_response);
        SecureFree(driverName);
        return StatusCode::MemoryAllocFailed;
    }
    LI_FN(GetTempPathA)(MAX_PATH, tempPath);

    CHAR* driverPath = (CHAR*)SecureAlloc(MAX_PATH);
    if (!driverPath) {
        SecureFree(mapper_response);
        SecureFree(driverName);
        SecureFree(tempPath);
        return StatusCode::MemoryAllocFailed;
    }

    LI_FN(sprintf)(driverPath, xorstr_("%s%s.bin"), tempPath, driverName);
    SecureFree(driverName);
    SecureFree(tempPath);

    if (!WriteFileFromBuffer(driverPath, mapper_response + 8, mapper_response_size - 8)) {
        SecureFree(mapper_response);
        LI_FN(DeleteFileA)(driverPath);
        SecureFree(driverPath);
        return StatusCode::FileWriteFailed;
    }
    SecureFree(mapper_response);

    *outDriverPath = driverPath;
    return StatusCode::Success;
}

__declspec(noinline) ULONG64 RequestDSEToTempFile(_Globals* Globals, CHAR** outDsePath) {
    CHAR* dse_request = (CHAR*)SecureAlloc(MAX_PATH);
    if (!dse_request) return StatusCode::MemoryAllocFailed;
    LI_FN(sprintf)(dse_request, xorstr_("UN_DSE_Extractor*%s*%s*%s"), Globals->SecretKey, xorstr_(""), Globals->hwid);

    CHAR* dse_response = NULL;
    INT dse_response_size = 0;
    if (!tcpRequest(xorstr_(""), 0, dse_request, &dse_response, &dse_response_size)) {
        SecureFree(dse_request);
        if (dse_response) SecureFree(dse_response);
        return StatusCode::DseRequestFailed;
    }
    SecureFree(dse_request);
    if (!verifyDataSource(dse_response, xorstr_(""))) {
        SecureFree(dse_response);
        return StatusCode::DataSourceVerifyFailed;
    }

    CHAR* driverName2 = GenerateRandomString(8);
    if (!driverName2) {
        SecureFree(dse_response);
        return StatusCode::MemoryAllocFailed;
    }

    CHAR* dsePath = (CHAR*)SecureAlloc(MAX_PATH);
    if (!dsePath) {
        SecureFree(dse_response);
        SecureFree(driverName2);
        return StatusCode::MemoryAllocFailed;
    }

    CHAR* tempPath2 = (CHAR*)SecureAlloc(MAX_PATH);
    if (!tempPath2) {
        SecureFree(dse_response);
        SecureFree(driverName2);
        SecureFree(dsePath);
        return StatusCode::MemoryAllocFailed;
    }
    LI_FN(GetTempPathA)(MAX_PATH, tempPath2);
    LI_FN(sprintf)(dsePath, xorstr_("%s%s.bin"), tempPath2, driverName2);
    SecureFree(driverName2);
    SecureFree(tempPath2);

    if (!WriteFileFromBuffer(dsePath, dse_response + 8, dse_response_size - 8)) {
        SecureFree(dse_response);
        LI_FN(DeleteFileA)(dsePath);
        SecureFree(dsePath);
        return StatusCode::FileWriteFailed;
    }
    SecureFree(dse_response);

    *outDsePath = dsePath;
    return StatusCode::Success;
}

__declspec(noinline) ULONG64 LoadDriverViaService(CHAR* driverPath) {
    CHAR* svcDriverName = GenerateRandomString(8);
    if (!svcDriverName) return StatusCode::MemoryAllocFailed;

    if (!CreateServiceEx(driverPath, svcDriverName)) {
        SecureFree(svcDriverName);
        return StatusCode::ServiceFailed;
    }

    NTSTATUS AgentDriverStatus = StartServiceEx(svcDriverName);
    if (AgentDriverStatus != 0xC0000001) {
        DeleteServiceEx(svcDriverName);
        SecureFree(svcDriverName);
        return StatusCode::ServiceFailed;
    }
    DeleteServiceEx(svcDriverName);
    SecureFree(svcDriverName);

    return StatusCode::Success;
}

__declspec(noinline) ULONG64 ExecuteDSELoad(CHAR* dsePath, CHAR* driverPath) {
    CHAR* cmdDisable = (CHAR*)SecureAlloc(MAX_PATH);
    if (!cmdDisable) return StatusCode::MemoryAllocFailed;

    LI_FN(sprintf)(cmdDisable, xorstr_("%s disable"), dsePath);

    STARTUPINFOA si1;
    PROCESS_INFORMATION pi1;
    __stosb((PBYTE)&si1, 0, sizeof(si1));
    __stosb((PBYTE)&pi1, 0, sizeof(pi1));
    si1.cb = sizeof(si1);
    si1.dwFlags = STARTF_USESHOWWINDOW;
    si1.wShowWindow = SW_HIDE;

    if (!LI_FN(CreateProcessA).in(LI_MODULE("KERNEL32.dll").get())(NULL, cmdDisable, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si1, &pi1)) {
        SecureFree(cmdDisable);
        return StatusCode::CmdCallFailed;
    }
    SecureFree(cmdDisable);
    LI_FN(WaitForSingleObject).in(LI_MODULE("KERNEL32.dll").get())(pi1.hProcess, 60000);
    LI_FN(CloseHandle)(pi1.hProcess);
    LI_FN(CloseHandle)(pi1.hThread);

    ULONG64 svcStatus = LoadDriverViaService(driverPath);

    CHAR* cmdRestore = (CHAR*)SecureAlloc(MAX_PATH);
    if (!cmdRestore) return svcStatus != StatusCode::Success ? svcStatus : StatusCode::MemoryAllocFailed;

    LI_FN(sprintf)(cmdRestore, xorstr_("%s restore"), dsePath);

    STARTUPINFOA si2;
    PROCESS_INFORMATION pi2;
    __stosb((PBYTE)&si2, 0, sizeof(si2));
    __stosb((PBYTE)&pi2, 0, sizeof(pi2));
    si2.cb = sizeof(si2);
    si2.dwFlags = STARTF_USESHOWWINDOW;
    si2.wShowWindow = SW_HIDE;

    if (!LI_FN(CreateProcessA).in(LI_MODULE("KERNEL32.dll").get())(NULL, cmdRestore, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
        SecureFree(cmdRestore);
        return svcStatus != StatusCode::Success ? svcStatus : StatusCode::CmdCallFailed;
    }
    SecureFree(cmdRestore);
    LI_FN(WaitForSingleObject).in(LI_MODULE("KERNEL32.dll").get())(pi2.hProcess, 60000);
    LI_FN(CloseHandle)(pi2.hProcess);
    LI_FN(CloseHandle)(pi2.hThread);

    return svcStatus;
}

__declspec(noinline) ULONG64 DriverInit(ULONG_PTR Key, BOOL Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    ULONG64 PreVerifyStatus = PreVerifySecretKeyForProduct(Globals);
    if (Globals->source != (ULONG_PTR)NtCurrentTeb()->ProcessEnvironmentBlock) return StatusCode::AppKeyInvalid;
    if (PreVerifyStatus != StatusCode::Success) return PreVerifyStatus;
    if (GetVerifyCode(Globals)) return StatusCode::Success;
    if (!ChangePrivilege(TRUE)) return StatusCode::NoPrivilege;

    CHAR* shellcode = NULL;
    INT shellcodeSize = 0;
    ULONG64 shellStatus = RequestShellcodeFromServer(Globals, &shellcode, &shellcodeSize);
    if (shellStatus != StatusCode::Success) return shellStatus;

    CHAR* driverPath = NULL;
    ULONG64 status = RequestMapperToTempFile(Globals, Type, &driverPath);
    if (status != StatusCode::Success) {
        __stosb((PBYTE)(shellcode - 8), 0, shellcodeSize + 8);
        SecureFree(shellcode - 8);
        return status;
    }

    CHAR* dsePath = NULL;
    if (Type) {
        status = RequestDSEToTempFile(Globals, &dsePath);
        if (status != StatusCode::Success) {
            LI_FN(DeleteFileA)(driverPath);
            SecureFree(driverPath);
            __stosb((PBYTE)(shellcode - 8), 0, shellcodeSize + 8);
            SecureFree(shellcode - 8);
            return status;
        }
    }

    USHORT lbPort = (USHORT)31337;
    ULONG_PTR lbParams[3] = { (ULONG_PTR)shellcode, (ULONG_PTR)shellcodeSize, (ULONG_PTR)lbPort };
    HANDLE hLbThread = LI_FN(CreateThread).in(LI_MODULE("KERNEL32.dll").get())(nullptr, 0, ServeShellcodeLoopback, lbParams, 0, nullptr);
    if (!hLbThread) {
        if (dsePath) {
            LI_FN(DeleteFileA)(dsePath);
            SecureFree(dsePath);
        }
        LI_FN(DeleteFileA)(driverPath);
        SecureFree(driverPath);
        __stosb((PBYTE)(shellcode - 8), 0, shellcodeSize + 8);
        SecureFree(shellcode - 8);
        return StatusCode::LoopbackThreadFailed;
    }

    if (Type) status = ExecuteDSELoad(dsePath, driverPath);
    else status = LoadDriverViaService(driverPath);

    if (dsePath) {
        LI_FN(DeleteFileA)(dsePath);
        SecureFree(dsePath);
    }
    LI_FN(DeleteFileA)(driverPath);
    SecureFree(driverPath);

    DWORD waitResult = LI_FN(WaitForSingleObject).in(LI_MODULE("KERNEL32.dll").get())(hLbThread, 60000);
    if (waitResult != WAIT_OBJECT_0) {
        LI_FN(TerminateThread).in(LI_MODULE("KERNEL32.dll").get())(hLbThread, 0);
        LI_FN(WaitForSingleObject).in(LI_MODULE("KERNEL32.dll").get())(hLbThread, 5000);
    }
    LI_FN(CloseHandle)(hLbThread);

    __stosb((PBYTE)(shellcode - 8), 0, shellcodeSize + 8);
    SecureFree(shellcode - 8);

    if (status != StatusCode::Success) return status;

    ChangePrivilege(FALSE);
    if (GetVerifyCode(Globals)) return StatusCode::Success;
    return StatusCode::DriverVerifyFailed;
}

__declspec(noinline) BOOL SetProcess(ULONG_PTR Key, INT ProcessId, BOOL DecryptCR3) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.ProcessId = ProcessId;
    Control.Type = DecryptCR3;

    parameter.Flag = UN_S_SetProcess;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL ProtectProcess(ULONG_PTR Key, INT ProcessId, BOOL Protect) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.ProcessId = ProcessId;
    Control.Type = Protect;

    parameter.Flag = UN_S_ProtectProcess;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) ULONG64 GetMainModuleBase(ULONG_PTR Key) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;

    parameter.Flag = UN_S_Get_ProcessBase;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer;
}

__declspec(noinline) ULONG64 GetProcessEnvironmentBlock(ULONG_PTR Key) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;

    parameter.Flag = UN_S_GET_ProcessPeb;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer;
}

__declspec(noinline) ULONG64 GetKernelModuleAddress(ULONG_PTR Key, CONST CHAR* ModuleName) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Buffer = (ULONG64)AnsiToWide(ModuleName);

    parameter.Flag = UN_S_GetKernelModuleAddress;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    SecureFree((HLOCAL)Control.Buffer);

    return outputbuffer;
}

__declspec(noinline) BOOL OperatePhysicalMemory(ULONG_PTR Key, ULONG64 Address, VOID* Buffer, INT Size, INT Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (Address <= 0 || Address > 0xFFFFFFFFFFFFFFFF || !Buffer || Size <= 0) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = Address;
    Control.Size = Size;
    Control.Buffer = (ULONG64)Buffer;
    Control.Type = Type;

    parameter.Flag = UN_S_CopyGlobalPhysicalMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL OperateProcessMemory(ULONG_PTR Key, ULONG64 Address, VOID* Buffer, INT Size, INT Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (Address <= 0 || Address > 0x7FFFFFFFFFFF || !Buffer || Size <= 0) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = Address;
    Control.Size = Size;
    Control.Buffer = (ULONG64)Buffer;
    Control.Type = Type;

    parameter.Flag = UN_S_CopyPhysicalMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL OperateKernelVirtualMemory(ULONG_PTR Key, ULONG64 Address, VOID* Buffer, INT Size, INT Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (Address <= 0 || Address > 0xFFFFFFFFFFFFFFFF || !Buffer || Size <= 0) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = Address;
    Control.Size = Size;
    Control.Buffer = (ULONG64)Buffer;
    Control.Type = Type;

    parameter.Flag = UN_S_CopyKernelVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL OperateVirtualMemory(ULONG_PTR Key, ULONG64 Address, VOID* Buffer, INT Size, INT Type) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (Address <= 0 || Address > 0x7FFFFFFFFFFF || !Buffer || Size <= 0) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = Address;
    Control.Size = Size;
    Control.Buffer = (ULONG64)Buffer;
    Control.Type = Type;

    parameter.Flag = UN_S_CopyVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) ULONG64 ReadMsr(ULONG_PTR Key, ULONG64 MsrAddress, ULONG64* Buffer, ULONG BufferCount) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (!MsrAddress || !Buffer || !BufferCount || BufferCount > 64) return 0;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = MsrAddress;
    Control.Buffer = (ULONG64)Buffer;
    Control.Size = BufferCount;

    parameter.Flag = UN_S_CopyMsr;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer;
}

__declspec(noinline) BOOL AllocateMemory(ULONG_PTR Key, ULONG64* BaseAddress, ULONG64* RegionSize, ULONG AllocationType, ULONG Protect) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = *BaseAddress;
    Control.Size = *RegionSize;
    Control.ProcessId = Protect;
    Control.Type = AllocationType;

    parameter.Flag = UN_S_AllocateVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    *BaseAddress = Control.Address;
    *RegionSize = Control.Size;

    return outputbuffer == 0;
}

__declspec(noinline) BOOL ProtectMemory(ULONG_PTR Key, ULONG64* BaseAddress, ULONG64* RegionSize, ULONG NewProtect, ULONG* OldProtect) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = *BaseAddress;
    Control.Size = *RegionSize;
    Control.Type = NewProtect;

    parameter.Flag = UN_S_ProtectVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    *BaseAddress = Control.Address;
    *RegionSize = Control.Size;
    *OldProtect = Control.ProcessId;

    return outputbuffer == 0;
}

__declspec(noinline) ULONG64 QueryVirtualMemory(ULONG_PTR Key, ULONG64 Address, ULONG64* BaseAddress, ULONG64* AllocationProtect, ULONG64* Size) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = Address;

    parameter.Flag = UN_S_QueryVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    *BaseAddress = Control.Buffer;
    *AllocationProtect = Control.Type;
    *Size = Control.Size;

    return Control.ProcessId;
}

__declspec(noinline) BOOL FreeMemory(ULONG_PTR Key, ULONG64* BaseAddress, ULONG64* RegionSize, ULONG FreeType) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = *BaseAddress;
    Control.Size = *RegionSize;
    Control.Type = FreeType;

    parameter.Flag = UN_S_FreeVirtualMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    *BaseAddress = Control.Address;
    *RegionSize = Control.Size;

    return outputbuffer == 0;
}

__declspec(noinline) BOOL CreateRemoteThread(ULONG_PTR Key, ULONG64 StartAddress, ULONG64 StartParameter) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = StartAddress;
    Control.Type = StartParameter;

    parameter.Flag = UN_S_CreateUserThread;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) ULONG64 AllocateMemoryEx(ULONG_PTR Key, ULONG64 RegionSize) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Size = RegionSize;

    parameter.Flag = UN_S_AllocMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer;
}

__declspec(noinline) BOOL FreeMemoryEx(ULONG_PTR Key, ULONG64 BaseAddress, ULONG64 RegionSize) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Address = BaseAddress;
    Control.Size = RegionSize;

    parameter.Flag = UN_S_FreeMemory;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL MouseCallbackRip(ULONG_PTR Key, PVOID InputData) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Buffer = (ULONG64)InputData;

    parameter.Flag = UN_S_InjectMouseInput;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL MouseCallbackASM(ULONG_PTR Key, PVOID InputData) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.Buffer = (ULONG64)InputData;

    parameter.Flag = UN_S_ASMMouseInput;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) ULONG64 FeatureCodeSearch(ULONG_PTR Key, ULONG64 Address, PCHAR Code, INT CodeSize, INT Attribute) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;
    ULONG64 buffer = 0;

    Control.Address = Address;
    Control.Buffer = (ULONG64)Code;
    Control.Size = CodeSize;
    Control.Type = Attribute;
    Control.ProcessId = (ULONG64)&buffer;

    parameter.Flag = UN_S_SearchMemoryInProcessEx;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return buffer;
}

__declspec(noinline) BOOL SuspendThread(ULONG_PTR Key, INT ThreadId) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (!ThreadId) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.ProcessId = ThreadId;

    parameter.Flag = UN_S_SuspendThread;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}

__declspec(noinline) BOOL ResumeThread(ULONG_PTR Key, INT ThreadId) {
    _Globals* Globals = (_Globals*)(Key ^ GetXorKey());

    if (!ThreadId) return FALSE;

    DriverParameter parameter;
    ULONG64 outputbuffer;
    DriverControl Control;

    Control.ProcessId = ThreadId;

    parameter.Flag = UN_S_ResumeThread;
    parameter.UNKey = UN_MAGICNUMBER;
    parameter.Control = (ULONG64)&Control;
    parameter.OutputBuffer = (ULONG64)&outputbuffer;

    ((LSTATUS(__stdcall*)(HKEY, LPCSTR, DWORD, DWORD, BYTE*, DWORD))Globals->RegSetValueExA)
        (HKEY_CURRENT_USER, NULL, NULL, REG_BINARY, (BYTE*)&parameter, sizeof(parameter));

    return outputbuffer == 0;
}