struct _Globals {
    ULONG_PTR source;
    CHAR SecretKey[33];
    CHAR hwid[18];
    ULONG64 RegSetValueExA;
};

__forceinline HLOCAL SecureAlloc(SIZE_T Bytes) {
    return LI_FN(LocalAlloc)(LPTR, Bytes);
}

__forceinline HLOCAL SecureFree(HLOCAL Ptr) {
    __stosb((PBYTE)Ptr, 0, LI_FN(LocalSize)(Ptr));
    return LI_FN(LocalFree)(Ptr);
}

template<typename T>
class LocalPtr {
public:
    __forceinline LocalPtr(int size = 0) noexcept
        : size_(size)
        , ptr_(nullptr)
    {
        if (size_ > 0) {
            ptr_ = (T*)SecureAlloc(size_);
        }
    }
    __forceinline LocalPtr(const LocalPtr& other) noexcept
        : size_(other.size_)
        , ptr_(nullptr)
    {
        if (size_ > 0 && other.ptr_) {
            ptr_ = (T*)SecureAlloc(size_);
            __movsb((PBYTE)ptr_, (const PBYTE)other.ptr_, size_);
        }
    }
    __forceinline LocalPtr& operator=(const LocalPtr& other) noexcept {
        if (this != &other) {
            Cleanup();

            size_ = other.size_;
            if (size_ > 0 && other.ptr_) {
                ptr_ = (T*)SecureAlloc(size_);
                __movsb((PBYTE)ptr_, (const PBYTE)other.ptr_, size_);
            }
        }
        return *this;
    }
    __forceinline LocalPtr(LocalPtr&& other) noexcept
        : size_(other.size_)
        , ptr_(other.ptr_)
    {
        other.size_ = 0;
        other.ptr_ = nullptr;
    }
    __forceinline LocalPtr& operator=(LocalPtr&& other) noexcept {
        if (this != &other) {
            Cleanup();

            size_ = other.size_;
            ptr_ = other.ptr_;

            other.size_ = 0;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    __forceinline T* operator->() const noexcept {
        return ptr_;
    }
    __forceinline T operator&() const noexcept {
        return (T)ptr_;
    }
    __forceinline T& operator*() const noexcept {
        return *ptr_;
    }
    __forceinline operator T* () const noexcept {
        return ptr_;
    }
    __forceinline T* get() const noexcept {
        return ptr_;
    }
    __forceinline void reset(int newSize = 0) noexcept {
        Cleanup();
        size_ = newSize;
        if (size_ > 0) {
            ptr_ = (T*)SecureAlloc(size_);
        }
    }
    __forceinline bool valid() const noexcept {
        return ptr_ != nullptr && size_ > 0;
    }
    __forceinline SIZE_T size() const noexcept {
        return size_;
    }
    __forceinline ~LocalPtr() noexcept {
        Cleanup();
    }
private:
    __forceinline void Cleanup() noexcept {
        if (ptr_ && size_ > 0) {
            __stosb((PBYTE)ptr_, 0, size_);
            SecureFree(ptr_);
        }
        ptr_ = nullptr;
        size_ = 0;
    }
private:
    T* ptr_;
    SIZE_T size_;
};

__forceinline INT my_strcmp(CONST CHAR* s1, CONST CHAR* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(CONST UCHAR*)s1 - *(CONST UCHAR*)s2;
}

__declspec(noinline) wchar_t* AnsiToWide(CONST CHAR* ansiStr) {
    if (ansiStr == nullptr) return nullptr;

    INT numChars = LI_FN(MultiByteToWideChar)(CP_ACP, 0, ansiStr, -1, nullptr, 0);
    if (!numChars) return nullptr;

    WCHAR* wideStr = (WCHAR*)SecureAlloc(numChars * sizeof(WCHAR));
    if (!wideStr) return nullptr;

    if (LI_FN(MultiByteToWideChar)(CP_ACP, 0, ansiStr, -1, wideStr, numChars) == 0) {
        SecureFree(wideStr);
        return nullptr;
    }

    return wideStr;
}

__forceinline VOID LoadAndImportDlls() {
    LI_FN(LoadLibraryA)(xorstr_("ADVAPI32.dll"));
    LI_FN(LoadLibraryA)(xorstr_("Kernel32.dll"));
    LI_FN(LoadLibraryA)(xorstr_("Ws2_32.dll"));
}

__declspec(noinline) BOOL WriteFileFromBuffer(CONST CHAR* path, CHAR* buffer, INT size) {
    DWORD written = 0;
    HANDLE hFile = LI_FN(CreateFileA).forwarded()(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    BOOL writeResult = LI_FN(WriteFile).forwarded()(hFile, buffer, size, &written, NULL);
    LI_FN(CloseHandle)(hFile);
    return writeResult && (written == (DWORD)size);
}

__declspec(noinline) BOOL verifyDataSource(CONST CHAR* data, CONST CHAR* verify_data) {
    if (LI_FN(lstrlenA)(data) < 8) return FALSE;
    if (LI_FN(RtlCompareMemory)(data, verify_data, 8) == 8) return TRUE;
    return FALSE;
}

__declspec(noinline) CHAR* GenerateRandomString(INT length) {
    CONST CHAR* CHARACTERS = xorstr_("0x89abcdfghjstuv17no25w6pqrelm34yz");
    CONST INT CHARACTERS_LENGTH = 35;

    CHAR* random_string = (CHAR*)SecureAlloc(length + 1);
    for (INT i = 0; i < length; ++i) {

        ULONG64 rdtsc = __rdtsc();
        INT rdtsc_int = LOWORD(rdtsc);
        INT random_index = rdtsc_int % CHARACTERS_LENGTH;
        random_string[i] = CHARACTERS[random_index];
    }

    return random_string;
}

__declspec(noinline) BOOL IsRunningAsAdmin() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (LI_FN(OpenProcessToken).in(LI_MODULE("ADVAPI32.dll").get())(LI_FN(GetCurrentProcess)(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (LI_FN(GetTokenInformation).in(LI_MODULE("ADVAPI32.dll").get())(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) fRet = Elevation.TokenIsElevated;
    }
    if (hToken) LI_FN(CloseHandle)(hToken);
    return fRet;
}

__declspec(noinline) BOOL ChangePrivilege(BOOL enable) {
    HANDLE TokenHandle = NULL;
    if (!LI_FN(OpenProcessToken).in(LI_MODULE("ADVAPI32.dll").get())(LI_FN(GetCurrentProcess)(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle)) return FALSE;

    LUID luid = { 0 };
    if (!LI_FN(LookupPrivilegeValueW).in(LI_MODULE("ADVAPI32.dll").get())(NULL, xorstr_(L"SeLoadDriverPrivilege"), &luid)) {
        LI_FN(CloseHandle)(TokenHandle);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);

    BOOL result = LI_FN(AdjustTokenPrivileges).in(LI_MODULE("ADVAPI32.dll").get())(TokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    LI_FN(CloseHandle)(TokenHandle);

    return result && LI_FN(GetLastError)() == ERROR_SUCCESS;
}

__declspec(noinline) BOOL CreateServiceEx(CONST CHAR* path, CONST CHAR* name) noexcept {
    HKEY handle = NULL;

    CHAR* RegKey = (CHAR*)SecureAlloc(MAX_PATH);
    LI_FN(sprintf)(RegKey, xorstr_("System\\CurrentControlSet\\Services\\%s"), name);
    LSTATUS result = LI_FN(RegCreateKeyExA).in(LI_MODULE("ADVAPI32.dll").get())
        (HKEY_LOCAL_MACHINE, RegKey, 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &handle, NULL);
    SecureFree(RegKey);
    if (result != ERROR_SUCCESS) return FALSE;

    UCHAR Type = 1;
    result = LI_FN(RegSetValueExA).in(LI_MODULE("ADVAPI32.dll").get())(handle, xorstr_("Type"), NULL, REG_DWORD, &Type, 4u);
    if (result != ERROR_SUCCESS) {
        LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
        return FALSE;
    }

    UCHAR ErrorControl = 3;
    result = LI_FN(RegSetValueExA).in(LI_MODULE("ADVAPI32.dll").get())(handle, xorstr_("ErrorControl"), NULL, REG_DWORD, &ErrorControl, 4u);
    if (result != ERROR_SUCCESS) {
        LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
        return FALSE;
    }

    UCHAR Start = 3;
    result = LI_FN(RegSetValueExA).in(LI_MODULE("ADVAPI32.dll").get())(handle, xorstr_("Start"), NULL, REG_DWORD, &Start, 4u);
    if (result != ERROR_SUCCESS) {
        LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
        return FALSE;
    }

    CHAR* Path = (CHAR*)SecureAlloc(MAX_PATH);
    LI_FN(sprintf)(Path, xorstr_("\\??\\%s"), path);
    result = LI_FN(RegSetValueExA).in(LI_MODULE("ADVAPI32.dll").get())(handle, xorstr_("ImagePath"), NULL, REG_SZ, (BYTE*)Path, (DWORD)LI_FN(lstrlenA)(Path));
    SecureFree(Path);
    if (result != ERROR_SUCCESS) {
        LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
        return FALSE;
    }

    return ERROR_SUCCESS == LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
}

__declspec(noinline) NTSTATUS StartServiceEx(CONST CHAR* name) {
    FARPROC NtLoadDriver = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(xorstr_("ntdll.dll")), xorstr_("NtLoadDriver"));
    if (!NtLoadDriver) return FALSE;

    ANSI_STRING Ansi_Path = { 0 };
    UNICODE_STRING Unicode_Path = { 0 };

    CHAR* RegPath = (CHAR*)SecureAlloc(MAX_PATH);
    LI_FN(sprintf)(RegPath, xorstr_("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s"), name);
    LI_FN(RtlInitAnsiString)(&Ansi_Path, RegPath);
    LI_FN(RtlAnsiStringToUnicodeString)(&Unicode_Path, &Ansi_Path, true);
    NTSTATUS Result = ((NTSTATUS(__stdcall*)(PUNICODE_STRING))NtLoadDriver)(&Unicode_Path);
    SecureFree(RegPath);

    return Result;
}

__declspec(noinline) BOOL StopServiceEx(CONST CHAR* name) {
    FARPROC NtUnloadDriver = LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(xorstr_("ntdll.dll")), xorstr_("NtUnloadDriver"));
    if (!NtUnloadDriver) return FALSE;
    ANSI_STRING Ansi_Path = { 0 };
    UNICODE_STRING Unicode_Path = { 0 };

    CHAR* RegPath = (CHAR*)SecureAlloc(MAX_PATH);
    LI_FN(sprintf)(RegPath, xorstr_("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s"), name);
    LI_FN(RtlInitAnsiString)(&Ansi_Path, RegPath);
    LI_FN(RtlAnsiStringToUnicodeString)(&Unicode_Path, &Ansi_Path, true);
    BOOL Result = ((NTSTATUS(__stdcall*)(PUNICODE_STRING))NtUnloadDriver)(&Unicode_Path) == ERROR_SUCCESS;
    SecureFree(RegPath);

    return Result;
}

__declspec(noinline) BOOL DeleteRegistryKeyRecursive(HKEY hParentKey, CONST CHAR* subKeyName) {
    HKEY hKey = NULL;
    LSTATUS result = LI_FN(RegOpenKeyExA).in(LI_MODULE("ADVAPI32.dll").get())
        (hParentKey, subKeyName, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;

    CHAR subKeyNameBuffer[MAX_PATH];
    DWORD subKeyNameSize;
    FILETIME lastWriteTime;

    while (TRUE) {
        subKeyNameSize = MAX_PATH;
        result = LI_FN(RegEnumKeyExA).in(LI_MODULE("ADVAPI32.dll").get())
            (hKey, 0, subKeyNameBuffer, &subKeyNameSize, NULL, NULL, NULL, &lastWriteTime);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) {
            LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(hKey);
            return FALSE;
        }
        if (!DeleteRegistryKeyRecursive(hKey, subKeyNameBuffer)) {
            LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(hKey);
            return FALSE;
        }
    }

    LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(hKey);
    return LI_FN(RegDeleteKeyExA).in(LI_MODULE("ADVAPI32.dll").get())(hParentKey, subKeyName, KEY_WOW64_64KEY, 0) == ERROR_SUCCESS;
}

__declspec(noinline) BOOL DeleteServiceEx(CONST CHAR* name) {
    HKEY handle = NULL;
    LSTATUS result = LI_FN(RegOpenKeyExA).in(LI_MODULE("ADVAPI32.dll").get())
        (HKEY_LOCAL_MACHINE, xorstr_("System\\CurrentControlSet\\Services\\"), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &handle);
    if (result != ERROR_SUCCESS) return FALSE;

    BOOL success = DeleteRegistryKeyRecursive(handle, name);
    LI_FN(RegCloseKey).in(LI_MODULE("ADVAPI32.dll").get())(handle);
    return success;
}

__declspec(noinline) BOOL GetMachineCode(CHAR*& MachineCode) {
    CHAR* buffer = (CHAR*)SecureAlloc(1024);
    if (!buffer) return FALSE;

    INT offset = 0;
    INT cpuInfo[4];
    __stosb((PBYTE)cpuInfo, 0, sizeof(cpuInfo));
    __cpuid(cpuInfo, 1);
    offset += LI_FN(sprintf)(buffer + offset, xorstr_("%08X%08X"), cpuInfo[3], cpuInfo[0]);

    DWORD serialNumber;
    __stosb((PBYTE)&serialNumber, 0, sizeof(serialNumber));
    LI_FN(GetVolumeInformationA)(xorstr_("C:\\"), nullptr, 0, &serialNumber, nullptr, nullptr, nullptr, 0);
    offset += LI_FN(sprintf)(buffer + offset, xorstr_("%08X"), serialNumber);

    CHAR biosSerialNumber[256];
    __stosb((PBYTE)biosSerialNumber, 0, sizeof(biosSerialNumber));
    DWORD biosSerialNumberSize = sizeof(biosSerialNumber);
    LI_FN(GetSystemFirmwareTable)('RSMB', 0, biosSerialNumber, biosSerialNumberSize);
    offset += LI_FN(sprintf)(buffer + offset, xorstr_("%s"), biosSerialNumber);

    MachineCode = (CHAR*)SecureAlloc(18);
    if (!MachineCode) {
        SecureFree(buffer);
        return FALSE;
    }

    LI_FN(memset)(MachineCode, 0, 18);

    INT sum = 0;
    for (INT i = 0; i < offset; i++) {
        sum += buffer[i];
        MachineCode[i % 17] ^= buffer[i];
    }

    for (INT i = 0; i < 17; i++) {
        MachineCode[i] = (MachineCode[i] + sum) % 36;
        if (MachineCode[i] < 10)
            MachineCode[i] += '0';
        else
            MachineCode[i] += 'A' - 10;
    }
    MachineCode[17] = 0;

    SecureFree(buffer);
    return TRUE;
}