#include <Windows.h>

DWORD HashMeDjb2W(wchar_t* str);
DWORD HashMeDjb2A(char* str);


constexpr DWORD CompileHashMeDjb2W(const wchar_t* str)
{
	DWORD hash = 5381;
	int c = 0;

	while ((c = *str++)) {
		if (c >= 'A' && c <= 'Z') {
			c += ('a' - 'A');
		}
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

constexpr DWORD CompileHashMeDjb2A(const char* str)
{
	DWORD hash = 5381;
	int c = 0;

	while ((c = *str++)) {
		if (c >= 'A' && c <= 'Z') {
			c += ('a' - 'A');
		}
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}


// MODULE HASH

constexpr DWORD KERNEL32_HASH = CompileHashMeDjb2W(L"kernel32.dll");
constexpr DWORD NTDLL_HASH = CompileHashMeDjb2W(L"ntdll.dll");
constexpr DWORD WININET_HASH = CompileHashMeDjb2W(L"Wininet.dll");
constexpr DWORD CRYPTSP_HASH = CompileHashMeDjb2W(L"cryptsp.dll");
constexpr DWORD BCRYPT_HASH = CompileHashMeDjb2W(L"Bcrypt.dll");

// KERNEL32.DLL

constexpr DWORD VIRTUALLOC_HASH = CompileHashMeDjb2A("VirtualAlloc");
constexpr DWORD VIRTUALPROTECT_HASH = CompileHashMeDjb2A("VirtualProtect");
constexpr DWORD VIRTUALFREE_HASH = CompileHashMeDjb2A("VirtualFree");
constexpr DWORD CREATETHREAD_HASH = CompileHashMeDjb2A("CreateThread");
constexpr DWORD GETTHREADCONTEXT_HASH = CompileHashMeDjb2A("GetThreadContext");
constexpr DWORD SETTHREADCONTEXT_HASH = CompileHashMeDjb2A("SetThreadContext");
constexpr DWORD RESUMETHREAD_HASH = CompileHashMeDjb2A("ResumeThread");
constexpr DWORD BASETHREADINITTHUNK_HASH = CompileHashMeDjb2A("BaseThreadInitThunk");
constexpr DWORD HEAPCREATE_HASH = CompileHashMeDjb2A("HeapCreate");
constexpr DWORD WAITFORSINGLEOBJECT_HASH = CompileHashMeDjb2A("WaitForSingleObject");
constexpr DWORD SLEEP_HASH = CompileHashMeDjb2A("Sleep");
constexpr DWORD CREATEEVENTW_HASH = CompileHashMeDjb2A("CreateEventW");
constexpr DWORD CREATETIMERQUEUE_HASH = CompileHashMeDjb2A("CreateTimerQueue");
constexpr DWORD CREATETIMERQUEUETIMER_HASH = CompileHashMeDjb2A("CreateTimerQueueTimer");
constexpr DWORD DELETETIMERQUEUE_HASH = CompileHashMeDjb2A("DeleteTimerQueue");
constexpr DWORD SETEVENT_HASH = CompileHashMeDjb2A("SetEvent");
constexpr DWORD QUEUEUSERAPC_HASH = CompileHashMeDjb2A("QueueUserApc");
constexpr DWORD CLOSEHANDLE_HASH = CompileHashMeDjb2A("CloseHandle");
constexpr DWORD HEAPWALK_HASH = CompileHashMeDjb2A("HeapWalk");
constexpr DWORD GETPROCESSHEAP_HASH = CompileHashMeDjb2A("GetProcessHeap");
constexpr DWORD EXITTHREAD_HASH = CompileHashMeDjb2A("ExitThread");
constexpr DWORD TERMINATETHREAD_HASH = CompileHashMeDjb2A("TerminateThread");
constexpr DWORD HEAPFREE_HASH = CompileHashMeDjb2A("HeapFree");
constexpr DWORD HEAPDESTROY_HASH = CompileHashMeDjb2A("HeapDestroy");
constexpr DWORD WAITFORSINGLEOBJECTEX_HASH = CompileHashMeDjb2A("WaitForSingleObjectEx");
constexpr DWORD TLSALLOC_HASH = CompileHashMeDjb2A("TlsAlloc");
constexpr DWORD HEAPALLOC_HASH = CompileHashMeDjb2A("HeapAlloc");

// NTDLL.DLL

constexpr DWORD LDRLOADDLL_HASH = CompileHashMeDjb2A("LdrLoadDll");
constexpr DWORD RTLANSISTRINGTOUNICODESTRING_HASH = CompileHashMeDjb2A("RtlAnsiStringToUnicodeString");
constexpr DWORD LDRGERPOCEDUREADDRESS_HASH = CompileHashMeDjb2A("LdrGetProcedureAddress");
constexpr DWORD RTLLOOKUPFUNCTIONENTRY_HASH = CompileHashMeDjb2A("RtlLookupFunctionEntry");
constexpr DWORD RTLUSERTHREADSTART_HASH = CompileHashMeDjb2A("RtlUserThreadStart");
constexpr DWORD TPRELEASECLEANUPGROUPMEMBERS_HASH = CompileHashMeDjb2A("TpReleaseCleanupGroupMembers");
constexpr DWORD DBGPRINT_HASH = CompileHashMeDjb2A("DbgPrint");
constexpr DWORD NTCONTINUE_HASH = CompileHashMeDjb2A("NtContinue");
constexpr DWORD RTLCAPTURECONTEXT_HASH = CompileHashMeDjb2A("RtlCaptureContext");
constexpr DWORD NTSETINFORMATIONVIRTUALMEMORY_HASH = CompileHashMeDjb2A("NtSetInformationVirtualMemory");
constexpr DWORD NTQUERYVIRTUALMEMORY_HASH = CompileHashMeDjb2A("NtQueryVirtualMemory");
constexpr DWORD NTTESTALERT_HASH = CompileHashMeDjb2A("NtTestAlert");
constexpr DWORD NTALERTRESUMETHREAD_HASH = CompileHashMeDjb2A("NtAlertResumeThread");
constexpr DWORD RTLEXITUSERTHREAD_HASH = CompileHashMeDjb2A("RtlExitUserThread");
constexpr DWORD NTFREEVIRTUALMEMORY_HASH = CompileHashMeDjb2A("NtFreeVirtualMemory");
constexpr DWORD RTLRANDOM_HASH = CompileHashMeDjb2A("RtlRandom");
constexpr DWORD NTSIGNALANDWAITFORSINGLEOBJECT_HASH = CompileHashMeDjb2A("NtSignalAndWaitForSingleObject");
constexpr DWORD NTRESUMETHREAD_HASH = CompileHashMeDjb2A("NtResumeThread");
constexpr DWORD NTTERMINATETHREAD_HASH = CompileHashMeDjb2A("NtTerminateThread");
constexpr DWORD RTLFLSFREE_HASH = CompileHashMeDjb2A("RtlFlsFree");
constexpr DWORD RTLALLOCATEHEAP_HASH = CompileHashMeDjb2A("RtlAllocateHeap");

// WININIET.DLL

constexpr DWORD INTERNETCLOSEHANDLE_HASH = CompileHashMeDjb2A("InternetCloseHandle");					
constexpr DWORD INTERNETREADFILE_HASH = CompileHashMeDjb2A("InternetReadFile");							
constexpr DWORD INTERNETCONNECTA_HASH = CompileHashMeDjb2A("InternetConnectA");							
constexpr DWORD INTERNETQUERYDATAAVAILABLE_HASH = CompileHashMeDjb2A("InternetQueryDataAvailable");		
constexpr DWORD INTERNETQUERYOPTIONA_HASH = CompileHashMeDjb2A("InternetQueryOptionA");					
constexpr DWORD INTERNETSETOPTIONA_HASH = CompileHashMeDjb2A("InternetSetOptionA");						
constexpr DWORD INTERNETSETSTATUSCALLBACK_HASH = CompileHashMeDjb2A("InternetSetStatusCallback");		
constexpr DWORD HTTPOPENREQUESTA_HASH = CompileHashMeDjb2A("HttpOpenRequestA");							
constexpr DWORD HTTPADDREQUESTHEADERSA_HASH = CompileHashMeDjb2A("HttpAddRequestHeadersA");				
constexpr DWORD HTTPSENDREQUESTA_HASH = CompileHashMeDjb2A("HttpSendRequestA");							
constexpr DWORD HTTPQUERYINFOA_HASH = CompileHashMeDjb2A("HttpQueryInfoA");
constexpr DWORD INTERNETOPENA_HASH = CompileHashMeDjb2A("InternetOpenA");								

// CRYPTSP.DLL

constexpr DWORD SYSTEMFUNCTION032_HASH = CompileHashMeDjb2A("SystemFunction032");

