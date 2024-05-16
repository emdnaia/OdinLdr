#include <Windows.h>

#include "instance.h"
#include "spoof.h"
#include "api.h"
#include "ntdll.h"

#pragma code_seg(".text$f")
PVOID xLoadLibraryA(LPCSTR lpLibFileName, PINSTANCE Inst)
{
	ANSI_STRING strDll = { 0 };
	UNICODE_STRING uniDll = { 0 };

	strDll.Buffer = (PCHAR)lpLibFileName;
	strDll.Length = strDll.MaximumLength = _strlenA((PBYTE)lpLibFileName);

	SPOOF_3(Inst->ntdll.RtlAnsiStringToUnicodeString, &uniDll, &strDll, (void*)TRUE);

	void* pModuleAddr = NULL;

	SPOOF_4(Inst->ntdll.LdrLoadDll, NULL, NULL, &uniDll, &pModuleAddr);

	return pModuleAddr;
}

#pragma code_seg(".text$f")
void* xLdrGetProcedureAddress(HMODULE hMod, LPSTR lpFunctionName, PINSTANCE Inst)
{

	ANSI_STRING ansiStr;
	ansiStr.Buffer = lpFunctionName;
	ansiStr.Length = ansiStr.MaximumLength = (USHORT)_strlenA((PBYTE)lpFunctionName);

	HMODULE hModule = NULL;
	void* pFunctionAddr = NULL;
	SPOOF_4(Inst->ntdll.LdrGetProcedureAddress, hMod, &ansiStr, (void*)0, &pFunctionAddr);

	return pFunctionAddr;
}

#pragma code_seg(".text$f")
void* xAllocAddr(SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, PINSTANCE Inst)
{
	void* ret = SPOOF_4(Inst->k32.VirtualAlloc, NULL, (void*)dwSize, (void*)flAllocationType, (void*)flProtect);
	return ret;

}

#pragma code_seg(".text$f")
HANDLE xHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, DWORD dwMaximumSize, PINSTANCE Inst)
{
	HANDLE hHeap = SPOOF_3(Inst->k32.HeapCreate, (void*)flOptions, (void*)dwInitialSize, (void*)dwMaximumSize);
	return hHeap;
}