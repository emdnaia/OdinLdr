#include <Windows.h>

#include "instance.h"

PVOID xLoadLibraryA(LPCSTR lpLibFileName, PINSTANCE Inst);
void* xLdrGetProcedureAddress(HMODULE hMod, LPSTR lpFunctionName, PINSTANCE Inst);
void* xAllocAddr(SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, PINSTANCE Inst);
HANDLE xHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, DWORD dwMaximumSize, PINSTANCE Inst);