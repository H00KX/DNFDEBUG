#pragma once
#include "NtHread.h"
#include "W7TwoMachineDebugging.h"
#ifdef __cplusplus
extern "C"
{
#endif
	NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pPDriverObj, _In_ PUNICODE_STRING pRegistryPath);
	VOID UnLoadDriver(_In_  PDRIVER_OBJECT pPDriverObj);

#ifdef __cplusplus
}
#endif