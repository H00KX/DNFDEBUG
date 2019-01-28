#include "Driver.h"
static W7TwoMachineDebugging g_W7TwoMachineDebugging;
NTSTATUS DriverEntry(PDRIVER_OBJECT pPDriverObj, PUNICODE_STRING pRegistryPath)
{
	g_W7TwoMachineDebugging.Init_W7TwoMachineDebuggingClass();
	OutError(g_W7TwoMachineDebugging.W7TwoMachineDebugging_Tp_Init());
	OutError(g_W7TwoMachineDebugging.HookKdDebuggerEnabled());
	OutError(g_W7TwoMachineDebugging.HookKdPitchDebugger());
	pPDriverObj->DriverUnload = UnLoadDriver;
	return STATUS_SUCCESS;
}

VOID UnLoadDriver(PDRIVER_OBJECT pPDriverObj)
{

}
