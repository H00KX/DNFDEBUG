#include "W7TwoMachineDebugging.h"
/* 
   以下偏移是 Windows 7 7600 x64 下的偏移
*/
static ULONG64  g_KdPitchDebugger_Offset = 0x1E520A;
static ULONG64  g_KiDebugRoutine_Offset = 0x2A8370;
static ULONG64  g_KdpTrap_Offset = 0x4F4010;
static ULONG64  g_KdpStub_Offset = 0X13BF30;

/* 
  KeUpdateSystemTime 第一处引用 KdDebuggerEnabled 的地方
*/
static ULONG64  g_KeUpdateSystemTime_KdDebuggerEnabled_OffeSet1 = 0x7A45D;

/*
  KeUpdateSystemTime 第二处引用 KdDebuggerEnabled 的地方
*/
static ULONG64  g_KeUpdateSystemTime_KdDebuggerEnabled_OffeSet2 = 0x7A5FB;


/*
    KeUpdateRunTime 第一处引用 KdDebuggerEnabled 的地方
*/
static ULONG64  g_KeUpdateRunTime_KdDebuggerEnabled_OffeSet1 = 0x7EE1C;

/*
	KdCheckForDebugBreak 第一处引用 KdDebuggerEnabled 的地方
*/
static ULONG64  g_KdCheckForDebugBreak_KdDebuggerEnabled_OffeSet1 = 0x116EDD;


/*
	KdPollBreakIn 第一处引用 KdDebuggerEnabled 的地方
*/
static ULONG64  g_KdPollBreakIn_KdDebuggerEnabled_OffeSet1 = 0x7EECC;


VOID W7TwoMachineDebugging::Init_W7TwoMachineDebuggingClass()
{
	m_Hook.Hook_Init();
}

NTSTATUS W7TwoMachineDebugging::W7TwoMachineDebugging_Tp_Init()
{
	NTSTATUS Status = STATUS_SUCCESS;
	m_NtBaseAddr = FastFunction::GetSystemModuleBase("ntoskrnl.exe");
	if (m_NtBaseAddr == 0) {
		Status = MY_GET_NTBASEADDR_ERROR;
		return Status;
	}
	m_KdEnteredDebugger_BL =  (ULONG64)FastFunction:: GetProcAddress(L"KdEnteredDebugger");
	if (m_KdEnteredDebugger_BL == 0) {
		Status = MY_GET_KDENTRREDDEBUGGER_ERROR;
		return Status;
	}

	m_KdDebuggerNotPresent_BL = (ULONG64)FastFunction::GetProcAddress(L"KdDebuggerNotPresent");
	if (m_KdDebuggerNotPresent_BL == 0) {
		Status = MY_GET_KDDEBUGGERNOTPRESENT_ERROR;
		return Status;
	}

	m_KdDebuggerEnabled_BL = (ULONG64)FastFunction::GetProcAddress(L"KdDebuggerEnabled");
	if (m_KdDebuggerNotPresent_BL == 0) {
		Status = MY_GET_KDDEBUGGERENABLED_ERROR;
		return Status;
	}

	m_KdPitchDebugger_BL = m_NtBaseAddr + g_KdPitchDebugger_Offset;
	if (!MmIsAddressValid((PVOID)m_KdPitchDebugger_BL)) {
		Status = MY_GET_KDPITCHDEBUGGER_ERROR;
			return Status;
	}

	m_KiDebugRoutine_BL = m_NtBaseAddr + g_KiDebugRoutine_Offset;
	if (!MmIsAddressValid((PVOID)m_KiDebugRoutine_BL)) {
		Status = MY_GET_KIDEBUGROUTINE_ERROR;
		return Status;
	}
	
	m_KdpTrap_HS = m_NtBaseAddr + g_KdpTrap_Offset;
	if (!MmIsAddressValid((PVOID)m_KdpTrap_HS)) {
		Status = MY_GET_KDPTRAP_ERROR;
		return Status;
	}
	
	m_KdpStub_HS = m_NtBaseAddr + g_KdpStub_Offset;
	if (!MmIsAddressValid((PVOID)m_KdpStub_HS)) {
		Status = MY_GET_KDPSTUB_ERROR;
		return Status;
	}
	__try
	{
		m_KdDebuggerEnabled_Me = (PULONG64)(m_NtBaseAddr + 0x1000 - 8);
		m_KdPitchDebugger_Me = (PULONG64)(m_NtBaseAddr + 0x1000 - 8 - 8);
		m_KdDebuggerNotPresent_Me = (PULONG64)(m_NtBaseAddr + 0x1000 - 8 - 8 - 8);
		*m_KdDebuggerEnabled_Me = *(PULONG64)m_KdDebuggerEnabled_BL;
		*m_KdPitchDebugger_Me = *(PULONG64)m_KdPitchDebugger_BL;
		*m_KdDebuggerNotPresent_Me = *(PULONG64)m_KdDebuggerNotPresent_BL;
	}
	__except (1) {
		Status = MY_GET_MOV_ERROR;
		return Status;
	}
	
	return Status;
}

NTSTATUS W7TwoMachineDebugging::HookKdDebuggerEnabled()
{
	NTSTATUS Status = STATUS_SUCCESS;	
	KIRQL Irql = WPOFFx64();
	__try
	{
	
		ULONG64 KeUpdateSystemTime_1 = m_NtBaseAddr + g_KeUpdateSystemTime_KdDebuggerEnabled_OffeSet1;
		ULONG64 KeUpdateSystemTime_2 = m_NtBaseAddr + g_KeUpdateSystemTime_KdDebuggerEnabled_OffeSet2;
		ULONG64 KeUpdateRunTime_ = m_NtBaseAddr + g_KeUpdateRunTime_KdDebuggerEnabled_OffeSet1;
		ULONG64 KdCheckForDebugBreak_ = m_NtBaseAddr + g_KdCheckForDebugBreak_KdDebuggerEnabled_OffeSet1;
		ULONG64 KdPollBreakIn_ = m_NtBaseAddr + g_KdPollBreakIn_KdDebuggerEnabled_OffeSet1;
		*(PULONG)(KeUpdateSystemTime_1 + 2) = (ULONG)((ULONG64)m_KdDebuggerEnabled_Me - KeUpdateSystemTime_1 - 6);
		*(PULONG)(KeUpdateSystemTime_2 + 2) = (ULONG)((ULONG64)m_KdDebuggerEnabled_Me - KeUpdateSystemTime_2 - 7);
		*(PULONG)(KeUpdateRunTime_ + 2) = (ULONG)((ULONG64)m_KdDebuggerEnabled_Me - KeUpdateRunTime_ - 7);
		*(PULONG)(KdCheckForDebugBreak_ + 2) = (ULONG)((ULONG64)m_KdDebuggerEnabled_Me - KdCheckForDebugBreak_ - 7);
		*(PULONG)(KdPollBreakIn_ + 3) = (ULONG)((ULONG64)m_KdDebuggerEnabled_Me - KdPollBreakIn_ - 7);
		*(PULONG64)m_KdDebuggerEnabled_BL = 0x100;
	}
	__except (1) {
		Status = MY_GET_MOV_ERROR;
		
	}
	WPONx64(Irql);
	return Status;
}

NTSTATUS W7TwoMachineDebugging::HookKdPitchDebugger()
{
	NTSTATUS Status = STATUS_SUCCESS;

	KIRQL Irql = WPOFFx64();

	WPONx64(Irql);

	return Status;
}
