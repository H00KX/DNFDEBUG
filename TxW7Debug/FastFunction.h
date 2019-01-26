#pragma once
#include "NtAPI.h"
namespace FastFunction
{

	ULONG64 GetSystemModuleBase(char* lpModuleName);
	VOID GetSystemModuleBase(char* lpModuleName, ULONG64 *ByRefBase, ULONG *ByRefSize);
	NTSTATUS HideDriver(char *pDrvName,PDRIVER_OBJECT pPDriverObj);
	PVOID RvaToVaHades(_In_ PVOID pModuleBase, _In_ ULONG Rva);
	PVOID GetModuleExport(_In_ PVOID pModuleBase, _In_ PCHAR pExportName);
	PVOID GetModuleBaseWow64(_In_ PEPROCESS pEProcess, _In_ PWCHAR pModuleName);
	PEPROCESS GetProcessPeprocess(int Pid);
	PVOID GetFunctionFromModule(_In_ PEPROCESS pEProcess, _In_ PWCHAR DllName, _In_ PCHAR FunctionName, BOOLEAN IsAttach);
	char* GetProcessNamebyHandle(HANDLE handle);
	PVOID GetProcAddress(PCWSTR FunctionName);

}