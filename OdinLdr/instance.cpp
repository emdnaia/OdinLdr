#include <Windows.h>

#include "hash.h"
#include "api.h"
#include "instance.h"

#pragma code_seg(".text$b")
BOOL InitInstance(PINSTANCE Inst)
{
	void* pKernel32 = xGetModuleAddr(KERNEL32_HASH);
	void* pNtdll = xGetModuleAddr(NTDLL_HASH);

	Inst->k32.VirtualAlloc = xGetProcAddr(pKernel32, VIRTUALLOC_HASH);
	if (Inst->k32.VirtualAlloc == NULL)
		return FALSE;

	Inst->k32.VirtualProtect = xGetProcAddr(pKernel32, VIRTUALPROTECT_HASH);
	if (Inst->k32.VirtualProtect == NULL)
		return FALSE;

	Inst->k32.VirtualFree = xGetProcAddr(pNtdll, NTFREEVIRTUALMEMORY_HASH);
	if (Inst->k32.VirtualFree == NULL)
		return FALSE;

	Inst->k32.CreateThread = xGetProcAddr(pKernel32, CREATETHREAD_HASH);
	if (Inst->k32.CreateThread == NULL)
		return FALSE;

	Inst->k32.GetThreadContext = xGetProcAddr(pKernel32, GETTHREADCONTEXT_HASH);
	if (Inst->k32.GetThreadContext == NULL)
		return FALSE;

	Inst->k32.SetThreadContext = xGetProcAddr(pKernel32, SETTHREADCONTEXT_HASH);
	if (Inst->k32.SetThreadContext == NULL)
		return FALSE;

	Inst->k32.ResumeThread = xGetProcAddr(pKernel32, RESUMETHREAD_HASH);
	if (Inst->k32.ResumeThread == NULL)
		return FALSE;
	
	Inst->k32.HeapCreate = xGetProcAddr(pKernel32, HEAPCREATE_HASH);
	if (Inst->k32.HeapCreate == NULL)
		return FALSE;

	Inst->ntdll.LdrLoadDll = xGetProcAddr(pNtdll, LDRLOADDLL_HASH);
	if (Inst->ntdll.LdrLoadDll == NULL)
		return FALSE;

	Inst->ntdll.RtlAnsiStringToUnicodeString = xGetProcAddr(pNtdll, RTLANSISTRINGTOUNICODESTRING_HASH);
	if (Inst->ntdll.RtlAnsiStringToUnicodeString == NULL)
		return FALSE;

	Inst->ntdll.LdrGetProcedureAddress = xGetProcAddr(pNtdll, LDRGERPOCEDUREADDRESS_HASH);
	if (Inst->ntdll.LdrGetProcedureAddress == NULL)
		return FALSE;

	Inst->ntdll.RtlLookupFunctionEntry = xGetProcAddr(pNtdll, RTLLOOKUPFUNCTIONENTRY_HASH);
	if (Inst->ntdll.RtlLookupFunctionEntry == NULL)
		return FALSE;

	Inst->ntdll.TpReleaseCleanupGroupMembers = xGetProcAddr(pNtdll, TPRELEASECLEANUPGROUPMEMBERS_HASH);
	if (Inst->ntdll.TpReleaseCleanupGroupMembers == NULL)
		return FALSE;

	Inst->ntdll.RtlCaptureContext = xGetProcAddr(pNtdll, RTLCAPTURECONTEXT_HASH);
	if (Inst->ntdll.RtlCaptureContext == NULL)
		return FALSE;

	Inst->ntdll.RtlExitUserThread = xGetProcAddr(pNtdll, RTLEXITUSERTHREAD_HASH);
	if (Inst->ntdll.RtlExitUserThread == NULL)
		return FALSE;

	Inst->ntdll.NtContinue = xGetProcAddr(pNtdll, NTCONTINUE_HASH);
	if (Inst->ntdll.NtContinue == NULL)
		return FALSE;

	return TRUE;
}

#pragma code_seg(".text$b")
BOOL InitInstanceAPC(PINSTANCE_APC Inst)
{
	void* pKernel32 = xGetModuleAddr(KERNEL32_HASH);
	void* pNtdll = xGetModuleAddr(NTDLL_HASH);
	void* pCryptsp = xGetModuleAddr(CRYPTSP_HASH);

	Inst->CloseHandle == xGetProcAddr(pKernel32, CLOSEHANDLE_HASH);
	if (Inst->CloseHandle = NULL)
		return FALSE;

	Inst->CreateEventW = xGetProcAddr(pKernel32, CREATEEVENTW_HASH);
	if (Inst->CreateEventW == NULL)
		return FALSE;

	Inst->CreateThread = xGetProcAddr(pKernel32, CREATETHREAD_HASH);
	if (Inst->CreateThread == NULL)
		return FALSE;

	Inst->GetThreadContext = xGetProcAddr(pKernel32, GETTHREADCONTEXT_HASH);
	if (Inst->GetThreadContext == NULL)
		return FALSE;

	Inst->QueueUserApc = xGetProcAddr(pKernel32, QUEUEUSERAPC_HASH);
	if (Inst->QueueUserApc == NULL)
		return FALSE;

	Inst->VirtualProtect = xGetProcAddr(pKernel32, VIRTUALPROTECT_HASH);
	if (Inst->VirtualProtect == NULL)
		return FALSE;
	
	Inst->CloseHandle = xGetProcAddr(pKernel32, CLOSEHANDLE_HASH);
	if (Inst->CloseHandle == NULL)
		return FALSE;
	
	Inst->WaitForSingleObject = xGetProcAddr(pKernel32, WAITFORSINGLEOBJECT_HASH);
	if (Inst->WaitForSingleObject == NULL)
		return FALSE;

	Inst->NtSignalAndWaitForSingleObject == xGetProcAddr(pNtdll, NTSIGNALANDWAITFORSINGLEOBJECT_HASH);
	if (Inst->NtSignalAndWaitForSingleObject = NULL)
		return FALSE;

	Inst->NtResumeThread = xGetProcAddr(pNtdll, NTRESUMETHREAD_HASH);
	if (Inst->NtResumeThread = NULL)
		return FALSE;

	Inst->NtContinue = xGetProcAddr(pNtdll, NTCONTINUE_HASH);
	if (Inst->NtContinue == NULL)
		return FALSE;

	Inst->NtTestAlert = xGetProcAddr(pNtdll, NTTESTALERT_HASH);
	if (Inst->NtTestAlert == NULL)
		return FALSE;

	Inst->RtlExitUserThread = xGetProcAddr(pNtdll, RTLEXITUSERTHREAD_HASH);
	if (Inst->RtlExitUserThread == NULL)
		return FALSE;

	Inst->TpReleaseCleanupGroupMembers = xGetProcAddr(pNtdll, TPRELEASECLEANUPGROUPMEMBERS_HASH);
	if (Inst->TpReleaseCleanupGroupMembers == NULL)
		return FALSE;

	Inst->RtlRandom = xGetProcAddr(pNtdll, RTLRANDOM_HASH);
	if (Inst->RtlRandom == NULL)
		return FALSE;

	Inst->NtQueryVirtualMemory = xGetProcAddr(pNtdll, NTQUERYVIRTUALMEMORY_HASH);
	if (Inst->NtQueryVirtualMemory == NULL)
		return FALSE;

	Inst->NtSetInformationVirtualMemory = xGetProcAddr(pNtdll, NTSETINFORMATIONVIRTUALMEMORY_HASH);
	if (Inst->NtSetInformationVirtualMemory == NULL)
		return FALSE;

	Inst->NtResumeThread = xGetProcAddr(pNtdll, NTRESUMETHREAD_HASH);
	if (Inst->NtResumeThread == NULL)
		return FALSE;

	Inst->NtSignalAndWaitForSingleObject = xGetProcAddr(pNtdll, NTSIGNALANDWAITFORSINGLEOBJECT_HASH);
	if (Inst->NtSignalAndWaitForSingleObject == NULL)
		return FALSE;

	Inst->SystemFunction032 = xGetProcAddr(pCryptsp, SYSTEMFUNCTION032_HASH);
	if (Inst->SystemFunction032 == NULL)
		return FALSE;

	return TRUE;
}

