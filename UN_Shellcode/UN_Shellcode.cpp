#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>

#include "Utils.hpp"
#include "CustomFunction.hpp"

#include "invlpg.hpp"
#include "Cr3Decrypt.hpp"
#include "CopyMsr.hpp"
#include "Process.hpp"
#include "Kernel.hpp"
#include "Virtual.hpp"

#include "AllocateFreeMemory.hpp"
#include "Memory.hpp"

#include "Mouse.hpp"

#include "FeatureCodeMatching.hpp"

#include "PEtool.hpp"
#include "Inject_Memory.hpp"
#include "Inject.hpp"

#include "Thread.hpp"

#pragma code_seg(".text$AAA") 

__declspec(noinline) NTSTATUS A00_RegistryCallback(PVOID a1, PVOID a2, PVOID a3, PVOID a4) {
	ULONG64 shellBase = (ULONG64)A00_RegistryCallback - 0x8;
	ULONG64 mapKey = DeriveKey(shellBase);

	ULONG32 lo32 = *(volatile ULONG32*)(shellBase + 0x0);
	ULONG32 hi32 = *(volatile ULONG32*)(shellBase + 0x4);
	ULONG64 pMapAddr = ((ULONG64)(hi32 ^ (ULONG32)(mapKey >> 32)) << 32) | (ULONG64)(lo32 ^ (ULONG32)mapKey);

	PMap Map = (PMap)pMapAddr;

	if (a1) return ((NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID))_IT(Map, Map->ImportTable.RtlGenerateClass5Guid))(a1, a2, a3, a4);
	if (!a2 || !a3) return STATUS_SUCCESS;

	REG_NOTIFY_CLASS Notify = (REG_NOTIFY_CLASS)(ULONG64)a2;
	switch (Notify) {
	case RegNtSetValueKey: {
		PREG_SET_VALUE_KEY_INFORMATION RegInfo = (PREG_SET_VALUE_KEY_INFORMATION)a3;
		if (RegInfo->Type == REG_BINARY && RegInfo->DataSize == sizeof(DriverParameter)) {
			PDriverParameter Parameter = (PDriverParameter)RegInfo->Data;

			if (Parameter->UNKey != 'UNS') return STATUS_SUCCESS;

			PDriverControl Control = (PDriverControl)Parameter->Control;
			switch (Parameter->Flag) {
			case UN_S_Ping: { // 握手
				*(ULONG64*)Parameter->OutputBuffer = Map->MEMORY_TAG.Nono;
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_SetProcess: { // 设置进程
				*(ULONG64*)Parameter->OutputBuffer = SetProcess(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_ProtectProcess: { // 保护进程
				*(ULONG64*)Parameter->OutputBuffer = ProtectProcess(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_Get_ProcessBase: { // 取主模块
				*(ULONG64*)Parameter->OutputBuffer = Map->Process.process_base;
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_GET_ProcessPeb: { // 取PEB
				*(ULONG64*)Parameter->OutputBuffer = Map->Process.CurrentPEB;
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_GetKernelModuleAddress: { // 取内核模块
				*(ULONG64*)Parameter->OutputBuffer = GetKernelModuleAddress(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CopyGlobalPhysicalMemory: { // 刷页全局
				*(ULONG64*)Parameter->OutputBuffer = CopyGlobalPhysicalMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CopyPhysicalMemory: { // 刷页
				*(ULONG64*)Parameter->OutputBuffer = CopyPhysicalMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CopyKernelVirtualMemory: { // 操作内核内存
				*(ULONG64*)Parameter->OutputBuffer = CopyKernelVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CopyVirtualMemory: { // 操作虚拟内存
				*(ULONG64*)Parameter->OutputBuffer = CopyVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CopyMsr: { // 读 MSR
				*(ULONG64*)Parameter->OutputBuffer = CopyMsr(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_AllocateVirtualMemory: { // 申请内存
				*(ULONG64*)Parameter->OutputBuffer = AllocateVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_ProtectVirtualMemory: { // 保护内存
				*(ULONG64*)Parameter->OutputBuffer = ProtectVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_QueryVirtualMemory: { // 查询属性
				*(ULONG64*)Parameter->OutputBuffer = QueryVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_FreeVirtualMemory: { // 释放内存
				*(ULONG64*)Parameter->OutputBuffer = FreeVirtualMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_CreateUserThread: { // 创建线程
				*(ULONG64*)Parameter->OutputBuffer = CreateUserThread(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_AllocMemory: { // 无附加申请
				*(ULONG64*)Parameter->OutputBuffer = AllocMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_FreeMemory: { // 无附加释放
				*(ULONG64*)Parameter->OutputBuffer = FreeMemory(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_InjectMouseInput: { // Rip派遣
				*(ULONG64*)Parameter->OutputBuffer = InjectMouseInput(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_ASMMouseInput: { // 自建汇编
				*(ULONG64*)Parameter->OutputBuffer = ASMMouseInput(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_SearchMemoryInProcessEx: { // 特征码搜索
				*(ULONG64*)Parameter->OutputBuffer = SearchMemoryInProcessEx(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_InjectDLL: { // 注入进程
				*(ULONG64*)Parameter->OutputBuffer = InjectDLL(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_Get_Inject_Data: { // 注入查询
				*(Inject_Data*)Parameter->OutputBuffer = Map->Inject.Inject_Data;
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_SuspendThread: { // 挂起线程
				*(ULONG64*)Parameter->OutputBuffer = SuspendThread(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			case UN_S_ResumeThread: { // 恢复线程
				*(ULONG64*)Parameter->OutputBuffer = ResumeThread(Map, Control);
				return STATUS_UNSUCCESSFUL;
			}
			}
		}
		break;
	}
	}
	return STATUS_SUCCESS;
}

#pragma code_seg() 