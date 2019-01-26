#include "NtHread.h"

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}




VOID OutPut(const char* fmt, ...)
{
	UNREFERENCED_PARAMETER(fmt);
	va_list ap;
	va_start(ap, fmt);
#ifdef DBG
	vKdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap));
#else
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap);
#endif 
	va_end(ap);
}

VOID OutError(NTSTATUS Code)
{
	switch (Code)
	{
	case MY_GET_NTBASEADDR_ERROR: {
		OutPut("��ȡ�ں˻�ַʧ��.\n");
		break;
	}
	case MY_GET_KDENTRREDDEBUGGER_ERROR: {
		OutPut("��ȡKdEnteredDebugger��ַʧ��\n");
		break;
	}

	case MY_GET_KDDEBUGGERNOTPRESENT_ERROR:{
		OutPut("��ȡKdDebuggerNotPresent��ַʧ��\n");
		break;
	}

	case MY_GET_KIDEBUGROUTINE_ERROR: {
		OutPut("��ȡKdPitchDebugger��ַʧ��\n");
		break;
	}
	case MY_GET_KDPTRAP_ERROR: {
		OutPut("��ȡKdpTrap��ַʧ��\n");
		break;
	}

	case MY_GET_KDPSTUB_ERROR: {
		OutPut("��ȡKdpStub��ַʧ��\n");
		break;
	}
	case MY_GET_KDDEBUGGERENABLED_ERROR:{
		OutPut("��ȡKdDebuggerEnabled��ַʧ��\n");
		break;
	}

	case  MY_GET_MOV_ERROR: {
		OutPut("ת�Ʊ���ʧ��\n");
		break;
	}
	default:
		break;
	}
}
