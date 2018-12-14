#pragma once

#include <windows.h>

extern unsigned char oldHookInternetOpenA[LEN_OPCODES_HOOK_FUNCTION];
void HookInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
);