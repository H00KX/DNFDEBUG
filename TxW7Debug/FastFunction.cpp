#include "FastFunction.h"



ULONG64 FastFunction::GetSystemModuleBase(char* lpModuleName)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	ModuleCount = pSystemModuleInformation->ModuleCount;

	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].ImageBase) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].PathLength;
			if (_stricmp(pDrvName, lpModuleName) == 0)
				return (ULONG64)pSystemModuleInformation->Module[i].ImageBase;
		}
	}
	kfree(pBuffer);
	return 0;
}

VOID FastFunction::GetSystemModuleBase(char * lpModuleName, ULONG64 * ByRefBase, ULONG * ByRefSize)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return;
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			kfree(pBuffer);
			return;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	ModuleCount = pSystemModuleInformation->ModuleCount;
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].ImageBase) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].PathLength;
			if (_stricmp(pDrvName, lpModuleName) == 0)
			{
				*ByRefBase = (ULONG64)pSystemModuleInformation->Module[i].ImageBase;
				*ByRefSize = pSystemModuleInformation->Module[i].ImageSize;
				goto exit_sub;
			}
		}
	}
exit_sub:
	kfree(pBuffer);
}

NTSTATUS FastFunction::HideDriver(char * pDrvName,PDRIVER_OBJECT pPDriverObj)
{
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pPDriverObj->DriverSection;
	PKLDR_DATA_TABLE_ENTRY firstentry;
	ULONG64 pDrvBase = 0;
	KIRQL OldIrql;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	firstentry = entry;
	pDrvBase = GetSystemModuleBase(pDrvName);
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if (entry->DllBase != 0)
		{
			if (entry->DllBase == pDrvBase)
			{
				OldIrql = KeRaiseIrqlToDpcLevel();
				((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
				((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;
				entry->InLoadOrderLinks.Flink = 0;
				entry->InLoadOrderLinks.Blink = 0;
				KeLowerIrql(OldIrql);
				Status = STATUS_SUCCESS;
				break;
			}
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return Status;
}

PVOID FastFunction::RvaToVaHades(PVOID pModuleBase, ULONG Rva)
{
	if (Rva == 0)
	{
		return NULL;
	}

	return (PVOID)((PUCHAR)pModuleBase + Rva);
}

PVOID FastFunction::GetModuleExport(PVOID pModuleBase, PCHAR pExportName)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)RvaToVaHades(pModuleBase, pDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders32;
	if (pNtHeaders64 == NULL || pNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pDataDirectory = &pNtHeaders64->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		pDataDirectory = &pNtHeaders32->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RvaToVaHades(pModuleBase, pDataDirectory->VirtualAddress);
	ULONG ExportDirectorySize = pDataDirectory->Size;
	if (pExportDirectory == NULL)
	{
		return NULL;
	}
	PULONG NameTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNames);
	PULONG AddressTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfFunctions);
	PUSHORT OrdinalsTable = (PUSHORT)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNameOrdinals);
	if (NameTable == NULL || AddressTable == NULL || OrdinalsTable == NULL)
	{
		return NULL;
	}
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		PCHAR pCurrentName = (PCHAR)RvaToVaHades(pModuleBase, NameTable[i]);

		if (pCurrentName != NULL && strncmp(pExportName, pCurrentName, 256) == 0)
		{
			USHORT CurrentOrd = OrdinalsTable[i];

			if (CurrentOrd < pExportDirectory->NumberOfFunctions)
			{
				PVOID pExportAddress = RvaToVaHades(pModuleBase, AddressTable[CurrentOrd]);

				if ((ULONG_PTR)pExportAddress >= (ULONG_PTR)pExportDirectory &&
					(ULONG_PTR)pExportAddress <= (ULONG_PTR)pExportDirectory + ExportDirectorySize)
				{
					return NULL;
				}
				return pExportAddress;
			}

			return NULL;
		}
	}

	return NULL;
}

PVOID FastFunction::GetModuleBaseWow64(PEPROCESS pEProcess, PWCHAR pModuleName)
{
	NTSTATUS nStatus;
	PPEB32 pPeb = NULL;
	UNICODE_STRING usModuleName = { 0 };
	RtlInitUnicodeString(&usModuleName, pModuleName);
	pPeb = (PPEB32)PsGetProcessWow64Process(pEProcess);
	if (pPeb == NULL || pPeb->Ldr == 0) {
		return NULL;
	}
	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
		pListEntry = (PLIST_ENTRY32)pListEntry->Flink) 
	{
		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		if (LdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}

		UNICODE_STRING usCurrentName = { 0 };
		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
		{
			return (PVOID)LdrEntry->DllBase;
			
		}
	}

	return NULL;

}

PEPROCESS FastFunction::GetProcessPeprocess(int Pid)
{
	PEPROCESS Pe = NULL;
	PsLookupProcessByProcessId((HANDLE)Pid, &Pe);
	return Pe;
}

PVOID FastFunction::GetFunctionFromModule(PEPROCESS pEProcess, PWCHAR DllName, PCHAR FunctionName,BOOLEAN IsAttach)
{
	KAPC_STATE KAPC = { 0 };
	PVOID BaseAddr = NULL;
	if (IsAttach) {
		KeStackAttachProcess(pEProcess, &KAPC);
	}
	PVOID pNtdllBase = GetModuleBaseWow64(pEProcess, DllName);
	if (pNtdllBase == NULL) {
		goto $EXIT;
	}
	BaseAddr = GetModuleExport(pNtdllBase, FunctionName);
$EXIT:
	if (IsAttach) {
		KeUnstackDetachProcess(&KAPC);
	}
	return BaseAddr;
}

char* FastFunction::GetProcessNamebyHandle(HANDLE handle)
{
	PEPROCESS Process;
	NTSTATUS status;
	char *nameptr = NULL;
	status = ObReferenceObjectByHandle(handle, 0, NULL, KernelMode, (PVOID *)&Process, NULL);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	return (char *)PsGetProcessImageFileName(Process);
}

PVOID FastFunction::GetProcAddress(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return MmGetSystemRoutineAddress(&UniCodeFunctionName);
}




