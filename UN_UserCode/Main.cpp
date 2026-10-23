#include <ws2tcpip.h>
#include <Windows.h>
#include <iostream>
#include <winternl.h>

#include "importer.hpp"
#include "xorstr.hpp"

#include "UserErrorCode.hpp"
#include "Utils.hpp"
#include "Web.hpp"

#include "UN_Driver.hpp"
#include "UN_GetModuleBase.hpp"
#include "UN_Inject.hpp"

enum {
    FunctionId_UN_InitAppKey,
    FunctionId_UN_DriverInit,

    FunctionId_UN_SetProcess,
    FunctionId_UN_ProtectProcess,
    FunctionId_UN_GetMainModuleBase,
    FunctionId_UN_GetProcessEnvironmentBlock,
    FunctionId_UN_GetKernelModuleAddress,
    FunctionId_UN_GetModuleAddress,
    FunctionId_UN_GetFunctionAddress,

    FunctionId_UN_OperatePhysicalMemory,
    FunctionId_UN_OperateProcessMemory,
    FunctionId_UN_OperateKernelVirtualMemory,
    FunctionId_UN_OperateVirtualMemory,
    FunctionId_UN_ReadMsr,

    FunctionId_UN_AllocateMemory,
    FunctionId_UN_ProtectMemory,
    FunctionId_UN_QueryVirtualMemory,
    FunctionId_UN_FreeMemory,
    FunctionId_UN_CreateRemoteThread,

    FunctionId_UN_AllocateMemoryEx,
    FunctionId_UN_FreeMemoryEx,

    FunctionId_UN_MouseCallback,
    FunctionId_UN_MouseCallbackASM,

    FunctionId_UN_FeatureCodeSearch,

    FunctionId_UN_InjectDLL,
    FunctionId_UN_GetInjectResult,

    FunctionId_UN_SuspendThread,
    FunctionId_UN_ResumeThread
};

__declspec(noinline) ULONG64 A0_UN_Call(ULONG64 Buffer = 0, ULONG64 FunctionId = 0, ULONG64 Key = 0, ULONG64 a1 = 0, ULONG64 a2 = 0, ULONG64 a3 = 0, ULONG64 a4 = 0) noexcept {
    switch (FunctionId) {
    case FunctionId_UN_InitAppKey:
        *(ULONG64*)Buffer = InitAppKey((CONST CHAR*)a1, (ULONG_PTR*)a2);
        break;
    case FunctionId_UN_DriverInit:
        *(ULONG64*)Buffer = DriverInit((ULONG_PTR)Key, (BOOL)a1);
        break;
    case FunctionId_UN_SetProcess:
        *(ULONG64*)Buffer = SetProcess((ULONG_PTR)Key, (INT)a1, (BOOL)a2);
        break;
    case FunctionId_UN_ProtectProcess:
        *(ULONG64*)Buffer = ProtectProcess((ULONG_PTR)Key, (INT)a1, (BOOL)a2);
        break;
    case FunctionId_UN_GetMainModuleBase:
        *(ULONG64*)Buffer = GetMainModuleBase((ULONG_PTR)Key);
        break;
    case FunctionId_UN_GetProcessEnvironmentBlock:
        *(ULONG64*)Buffer = GetProcessEnvironmentBlock((ULONG_PTR)Key);
        break;
    case FunctionId_UN_GetKernelModuleAddress:
        *(ULONG64*)Buffer = GetKernelModuleAddress((ULONG_PTR)Key, (CONST CHAR*)a1);
        break;
    case FunctionId_UN_GetModuleAddress:
        *(ULONG64*)Buffer = GetModuleAddress((ULONG_PTR)Key, (CONST CHAR*)a1, (INT)a2, (BOOL)a3);
        break;
    case FunctionId_UN_GetFunctionAddress:
        *(ULONG64*)Buffer = GetFunctionAddress((ULONG_PTR)Key, (ULONG64)a1, (CONST CHAR*)a2, (INT)a3);
        break;
    case FunctionId_UN_OperatePhysicalMemory:
        *(ULONG64*)Buffer = OperatePhysicalMemory((ULONG_PTR)Key, (ULONG64)a1, (VOID*)a2, (INT)a3, (INT)a4);
        break;
    case FunctionId_UN_OperateProcessMemory:
        *(ULONG64*)Buffer = OperateProcessMemory((ULONG_PTR)Key, (ULONG64)a1, (VOID*)a2, (INT)a3, (INT)a4);
        break;
    case FunctionId_UN_OperateKernelVirtualMemory:
        *(ULONG64*)Buffer = OperateKernelVirtualMemory((ULONG_PTR)Key, (ULONG64)a1, (VOID*)a2, (INT)a3, (INT)a4);
        break;
    case FunctionId_UN_OperateVirtualMemory:
        *(ULONG64*)Buffer = OperateVirtualMemory((ULONG_PTR)Key, (ULONG64)a1, (VOID*)a2, (INT)a3, (INT)a4);
        break;
    case FunctionId_UN_ReadMsr:
        *(ULONG64*)Buffer = ReadMsr((ULONG_PTR)Key, (ULONG64)a1, (ULONG64*)a2, (ULONG)a3);
        break;
    case FunctionId_UN_AllocateMemory:
        *(ULONG64*)Buffer = AllocateMemory((ULONG_PTR)Key, (ULONG64*)a1, (ULONG64*)a2, (ULONG)a3, (ULONG)a4);
        break;
    case FunctionId_UN_ProtectMemory:
        *(ULONG64*)Buffer = ProtectMemory((ULONG_PTR)Key, (ULONG64*)a1, (ULONG64*)a2, (ULONG)a3, (ULONG*)a4);
        break;
    case FunctionId_UN_QueryVirtualMemory:
        *(ULONG64*)Buffer = QueryVirtualMemory((ULONG_PTR)Key, (ULONG64)a1, (ULONG64*)a2, (ULONG64*)a3, (ULONG64*)a4);
        break;
    case FunctionId_UN_FreeMemory:
        *(ULONG64*)Buffer = FreeMemory((ULONG_PTR)Key, (ULONG64*)a1, (ULONG64*)a2, (ULONG)a3);
        break;
    case FunctionId_UN_CreateRemoteThread:
        *(ULONG64*)Buffer = CreateRemoteThread((ULONG_PTR)Key, (ULONG64)a1, (ULONG64)a2);
        break;
    case FunctionId_UN_AllocateMemoryEx:
        *(ULONG64*)Buffer = AllocateMemoryEx((ULONG_PTR)Key, (ULONG64)a1);
        break;
    case FunctionId_UN_FreeMemoryEx:
        *(ULONG64*)Buffer = FreeMemoryEx((ULONG_PTR)Key, (ULONG64)a1, (ULONG64)a2);
        break;
    case FunctionId_UN_MouseCallback:
        *(ULONG64*)Buffer = MouseCallbackRip((ULONG_PTR)Key, (PVOID)a1);
        break;
    case FunctionId_UN_MouseCallbackASM:
        *(ULONG64*)Buffer = MouseCallbackASM((ULONG_PTR)Key, (PVOID)a1);
        break;
    case FunctionId_UN_FeatureCodeSearch:
        *(ULONG64*)Buffer = FeatureCodeSearch((ULONG_PTR)Key, (ULONG64)a1, (PCHAR)a2, (INT)a3, (INT)a4);
        break;
    case FunctionId_UN_InjectDLL:
        *(ULONG64*)Buffer = InjectDLL((ULONG_PTR)Key, (CONST VOID*)a1, (ULONG64)a2, (INT)a3);
        break;
    case FunctionId_UN_GetInjectResult:
        *(ULONG64*)Buffer = GetInjectResult((ULONG_PTR)Key);
        break;
    case FunctionId_UN_SuspendThread:
        *(ULONG64*)Buffer = SuspendThread((ULONG_PTR)Key, (INT)a1);
        break;
    case FunctionId_UN_ResumeThread:
        *(ULONG64*)Buffer = ResumeThread((ULONG_PTR)Key, (INT)a1);
        break;
    default:
        return StatusCode::InvalidFunction;
    }
    return StatusCode::Success;
}

#ifdef _DEBUG

// ========== 输出辅助函数 ==========
static VOID PrintBanner(INT num, CONST CHAR* title) {
    printf("\n--------------------------------------------------\n");
    printf("  [%d] %s\n", num, title);
    printf("--------------------------------------------------\n");
}

static VOID PrintAddr(CONST CHAR* label, ULONG64 val) {
    printf("  %-26s: 0x%016llX\n", label, val);
}

static VOID PrintSize(CONST CHAR* label, ULONG64 val) {
    printf("  %-26s: 0x%llX (%llu bytes)\n", label, val, val);
}

static VOID PrintInt(CONST CHAR* label, INT val) {
    printf("  %-26s: %d\n", label, val);
}

static VOID PrintStatus(CONST CHAR* label, BOOL ok) {
    printf("  %-26s: [%s]\n", label, ok ? "  OK  " : " FAIL ");
}

static VOID PrintHex(CONST CHAR* label, CONST BYTE* p, INT n) {
    printf("  %-26s:", label);
    for (INT i = 0; i < n; i++) printf(" %02X", p[i]);
    printf("\n");
}

static VOID PrintNote(CONST CHAR* msg) {
    printf("  >> %s\n", msg);
}

static VOID PrintSub(CONST CHAR* title) {
    printf("  -- %s --\n", title);
}

INT main() {
    ULONG_PTR key = 0;
    ULONG64  Buffer = 0;

    // ---------- 1. 初始化密钥 ----------
    PrintBanner(1, "初始化密钥");
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_InitAppKey, 0, (ULONG64)"", (ULONG64)&key);
    if (Buffer != StatusCode::Success) {
        printf("  [FAIL] 初始化失败 Error: 0x%llX\n", Buffer);
        system("pause");
        return 1;
    }
    PrintStatus("初始化密钥", TRUE);

    // ---------- 2. 加载驱动 ----------
    PrintBanner(2, "加载驱动");
    printf("  1 - DSE 模式\n");
    printf("  0 - 服务模式\n");
    printf("  请选择: ");
    INT driverType = 0;
    scanf_s("%d", &driverType);
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_DriverInit, (ULONG64)key, (ULONG64)(driverType == 1));
    if (Buffer != StatusCode::Success) {
        printf("  [FAIL] 驱动加载失败 Error: 0x%llX\n", Buffer);
        system("pause");
        return 1;
    }
    PrintStatus("驱动加载", TRUE);

    // ---------- 3. 设置进程 ----------
    PrintBanner(3, "设置目标进程");
    HWND hwnd = FindWindowW(L"Progman", L"Program Manager");
    if (!hwnd) {
        PrintNote("找不到 explorer.exe 窗口");
        system("pause");
        return 1;
    }
    DWORD ProcessId = 0;
    GetWindowThreadProcessId(hwnd, &ProcessId);
    printf("  %-26s: %d\n", "explorer.exe PID", ProcessId);
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_SetProcess, (ULONG64)key, (ULONG64)ProcessId, (ULONG64)FALSE);
    PrintStatus("SetProcess", Buffer != 0);

    // ---------- 4. 模块/函数基址查询 ----------
    PrintBanner(4, "模块 / 函数基址查询");
    ULONG64 MainBase = 0, PEB = 0, KernelMod = 0, ntdllBase = 0, user32Base = 0, msgBoxA = 0;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetMainModuleBase, (ULONG64)key);                  MainBase = Buffer;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetProcessEnvironmentBlock, (ULONG64)key);         PEB = Buffer;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetKernelModuleAddress, (ULONG64)key, (ULONG64)"win32k.sys"); KernelMod = Buffer;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetModuleAddress, (ULONG64)key, (ULONG64)"ntdll.dll", 0, (ULONG64)TRUE); ntdllBase = Buffer;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetModuleAddress, (ULONG64)key, (ULONG64)"user32.dll", 0, (ULONG64)TRUE); user32Base = Buffer;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_GetFunctionAddress, (ULONG64)key, user32Base, (ULONG64)"MessageBoxA", 0); msgBoxA = Buffer;
    PrintAddr("主模块基址", MainBase);
    PrintAddr("PEB", PEB);
    PrintAddr("win32k.sys", KernelMod);
    PrintAddr("ntdll.dll", ntdllBase);
    PrintAddr("user32.dll", user32Base);
    PrintAddr("user32!MessageBoxA", msgBoxA);

    // ---------- 5. 内存读取测试 ----------
    PrintBanner(5, "内存读取测试 (20 bytes)");
    BYTE buf[20] = { 0 };

    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperatePhysicalMemory, (ULONG64)key, (ULONG64)0x1000, (ULONG64)buf, 20, 0);
    if (Buffer) PrintHex("Physical  @0x1000", buf, 20); else PrintNote("PhysicalMemory 读取失败");

    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, MainBase, (ULONG64)buf, 20, 0);
    if (Buffer) PrintHex("Process   @MainBase", buf, 20); else PrintNote("ProcessMemory 读取失败");

    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateKernelVirtualMemory, (ULONG64)key, KernelMod, (ULONG64)buf, 20, 0);
    if (Buffer) PrintHex("KernelV   @win32k.sys", buf, 20); else PrintNote("KernelVirtualMemory 读取失败");

    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, MainBase, (ULONG64)buf, 20, 0);
    if (Buffer) PrintHex("Virtual   @MainBase", buf, 20); else PrintNote("VirtualMemory 读取失败");

    // ---------- 6. AllocateMemoryEx / FreeMemoryEx ----------
    PrintBanner(6, "AllocateMemoryEx / FreeMemoryEx");
    ULONG64 ExAddr = 0;
    ULONG64 ExSize = 0x1000;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_AllocateMemoryEx, (ULONG64)key, ExSize);
    ExAddr = Buffer;
    if (!ExAddr) { PrintNote("申请内存失败"); }
    else {
        PrintAddr("申请内存", ExAddr);
        PrintSize("大小",     ExSize);

        PrintSub("写入 20000 (ProcessMemory)");
        INT val = 20000;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, ExAddr, (ULONG64)&val, sizeof(INT), 1);
        PrintStatus("写入", Buffer != 0);

        INT rd = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, ExAddr, (ULONG64)&rd, sizeof(INT), 0);
        if (Buffer) PrintInt("读回 (刷页)", rd); else PrintNote("读取失败");

        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_FreeMemoryEx, (ULONG64)key, ExAddr, ExSize);
        PrintStatus("FreeMemoryEx", Buffer != 0);
    }

    // ---------- 7. AllocateMemory / FreeMemory (附加读写) ----------
    PrintBanner(7, "AllocateMemory / FreeMemory (附加读写)");
    ULONG64 AlAddr = 0, AlSize = 0x1000;
    A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_AllocateMemory, (ULONG64)key, (ULONG64)&AlAddr, (ULONG64)&AlSize, (ULONG)(MEM_RESERVE | MEM_COMMIT), (ULONG)PAGE_EXECUTE_READWRITE);
    if (!AlAddr) { PrintNote("申请内存失败"); }
    else {
        PrintAddr("申请内存", AlAddr);
        PrintSize("大小",     AlSize);

        // Virtual 写/读
        PrintSub("Virtual 写/读 (附加)");
        INT v1 = 10000, r1 = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, AlAddr, (ULONG64)&v1, sizeof(INT), 1);
        PrintStatus("写入 10000", Buffer != 0);
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, AlAddr, (ULONG64)&r1, sizeof(INT), 0);
        if (Buffer) PrintInt("读回", r1); else PrintNote("读取失败");

        // Process 写/读 type=1 (刷页)
        PrintSub("Process 写/读 type=1 (刷页)");
        INT v2 = 20000, r2 = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, AlAddr, (ULONG64)&v2, sizeof(INT), 1);
        PrintStatus("写入 20000", Buffer != 0);
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, AlAddr, (ULONG64)&r2, sizeof(INT), 0);
        if (Buffer) PrintInt("读回", r2); else PrintNote("读取失败");

        // Process 写/读 type=2
        PrintSub("Process 写/读 type=2");
        INT v3 = 30000, r3 = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, AlAddr, (ULONG64)&v3, sizeof(INT), 2);
        PrintStatus("写入 30000", Buffer != 0);
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateProcessMemory, (ULONG64)key, AlAddr, (ULONG64)&r3, sizeof(INT), 0);
        if (Buffer) PrintInt("读回", r3); else PrintNote("读取失败");
    }

    // ---------- 8. ProtectMemory / QueryVirtualMemory ----------
    if (AlAddr) {
        PrintBanner(8, "ProtectMemory / QueryVirtualMemory");
        UINT OldProtect = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_ProtectMemory, (ULONG64)key, (ULONG64)&AlAddr, (ULONG64)&AlSize, (ULONG)PAGE_NOACCESS, (ULONG64)&OldProtect);
        printf("  %-26s: 0x%X\n", "修改 PAGE_NOACCESS 原属性", OldProtect);

        // 此处写入应失败 (PAGE_NOACCESS)
        INT v4 = 40000;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, AlAddr, (ULONG64)&v4, sizeof(INT), 1);
        printf("  %-26s: %s\n", "PAGE_NOACCESS 写入", Buffer ? "意外成功" : "已阻止 (预期)");

        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_ProtectMemory, (ULONG64)key, (ULONG64)&AlAddr, (ULONG64)&AlSize, (ULONG)PAGE_EXECUTE_READWRITE, (ULONG64)&OldProtect);
        printf("  %-26s: 0x%X\n", "恢复 RWX 原属性", OldProtect);

        // 恢复后写入应成功
        INT v5 = 50000, r5 = 0;
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, AlAddr, (ULONG64)&v5, sizeof(INT), 1);
        PrintStatus("恢复后写入 50000", Buffer != 0);
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_OperateVirtualMemory, (ULONG64)key, AlAddr, (ULONG64)&r5, sizeof(INT), 0);
        if (Buffer) PrintInt("读回", r5); else PrintNote("读取失败");

        // 查询属性
        PrintSub("QueryVirtualMemory");
        ULONG64 QryBase = 0, QryProtect = 0, QrySize = 0, QryType = 0;
        QryType = QueryVirtualMemory((ULONG_PTR)key, AlAddr, &QryBase, &QryProtect, &QrySize);
        if (QryType) {
            PrintAddr("Base",    QryBase);
            PrintAddr("Protect", QryProtect);
            PrintAddr("Size",    QrySize);
            CONST CHAR* pType = (QryType == 0x20000) ? "MEM_PRIVATE" :
                                (QryType == 0x40000) ? "MEM_MAPPED"  :
                                (QryType == 0x1000000) ? "MEM_IMAGE" : "UNKNOWN";
            printf("  %-26s: 0x%llX (%s)\n", "Type", QryType, pType);
        } else {
            PrintNote("QueryVirtualMemory 失败");
        }

        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_FreeMemory, (ULONG64)key, (ULONG64)&AlAddr, (ULONG64)&AlSize, MEM_RELEASE);
        PrintStatus("FreeMemory", Buffer != 0);
    }

    // ---------- 9. ReadMsr ----------
    PrintBanner(9, "ReadMsr 读取 MSR (IA32_TSC=0x10)");
    {
        ULONG64 msrValues[64] = { 0 };
        A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_ReadMsr, (ULONG64)key, (ULONG64)0x10, (ULONG64)msrValues, 64);
        if (Buffer && Buffer < 0x80000000ULL) {
            printf("  %-26s: %llu\n", "成功读取 CPU 数", Buffer);
            for (ULONG64 i = 0; i < Buffer; i++) {
                printf("  CPU[%-2llu] TSC                 : 0x%016llX\n", i, msrValues[i]);
            }
        }
        else {
            PrintNote("ReadMsr 失败");
        }
    }

    // ---------- 10. SuspendThread / ResumeThread ----------
    PrintBanner(10, "SuspendThread / ResumeThread");
    {
        // 自建工作线程: volatile 计数器每 1ms 自增
        static volatile LONG counter = 0;
        HANDLE hWorker = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
            for (;;) { _InterlockedIncrement((volatile LONG*)&counter); Sleep(1); }
        }, NULL, 0, NULL);
        if (!hWorker) {
            PrintNote("创建工作线程失败");
        }
        else {
            DWORD tid = GetThreadId(hWorker);
            printf("  %-26s: %u\n", "工作线程 TID", tid);

            auto Delta = [&](INT ms) -> LONG {
                LONG base = counter;
                Sleep(ms);
                return counter - base;
            };

            LONG running = Delta(300);
            printf("  %-26s: %ld\n", "挂起前增量 (300ms)", running);

            A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_SuspendThread, (ULONG64)key, (ULONG64)tid);
            PrintStatus("挂起线程", Buffer != 0);

            Sleep(100);                       // 等待 APC 交付生效
            LONG frozen = Delta(300);
            printf("  %-26s: %ld (预期 ≈0)\n", "挂起中增量 (300ms)", frozen);

            A0_UN_Call((ULONG64)&Buffer, FunctionId_UN_ResumeThread, (ULONG64)key, (ULONG64)tid);
            PrintStatus("恢复线程", Buffer != 0);

            Sleep(100);                       // 等待恢复生效
            LONG resumed = Delta(300);
            printf("  %-26s: %ld (预期 >0)\n", "恢复后增量 (300ms)", resumed);

            PrintStatus("挂起验证", frozen < running / 4);
            PrintStatus("恢复验证", resumed > running / 4);

            TerminateThread(hWorker, 0);
            CloseHandle(hWorker);
        }
    }

    printf("\n==================================================\n");
    printf("  测试结束\n");
    printf("==================================================\n");
    system("pause");
    return 0;
}
#endif