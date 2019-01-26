#pragma once
#include "HOOK.h"
#include "FastFunction.h"
class W7TwoMachineDebugging
{
public:
	VOID Init_W7TwoMachineDebuggingClass();
public:
	NTSTATUS W7TwoMachineDebugging_Tp_Init();
	NTSTATUS HookKdDebuggerEnabled();
	NTSTATUS HookKdPitchDebugger();
private:
	HOOK m_Hook;
	ULONG64 m_KdDebuggerEnabled_BL = 0;
	ULONG64 m_KdEnteredDebugger_BL = 0;
	ULONG64 m_KdDebuggerNotPresent_BL = 0;
	ULONG64 m_KdPitchDebugger_BL = 0;
	ULONG64 m_KiDebugRoutine_BL = 0;
	ULONG64 m_KdpTrap_HS = 0;
	ULONG64 m_KdpStub_HS = 0;
	ULONG64 m_NtBaseAddr = 0;
	//------------me---------------
	PULONG64 m_KdDebuggerEnabled_Me = 0;
	PULONG64 m_KdPitchDebugger_Me = 0;
	PULONG64 m_KdDebuggerNotPresent_Me = 0;
	PETHREAD m_THREADADD = 0;
};

