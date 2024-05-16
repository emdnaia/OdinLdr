#include <Windows.h>

#include "hook.h"

BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress);
void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PINSTANCE Inst, PHOOK_LIST hook, PLOADER_INFO info, UINT_PTR uiBeaconAddr, UINT_PTR uiBeaconSize);
void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress);