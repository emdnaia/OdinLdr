#pragma once
#include <Windows.h>

#include "instance.h"

VOID InitHook(PLOADER_INFO info, PHOOK_LIST hook, UINT_PTR uiBeaconAddr, UINT_PTR uiBeaconSize);
void* ResolveHook(LPCSTR functionName, PHOOK_LIST hook);

LPVOID InternetOpenA_Hook(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);

VOID Sleep_Hook(DWORD dwMs);