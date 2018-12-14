#include "stdafx.h"
#include "Util.h"
#include "ThreadLibraryHooks.h"


unsigned char oldHookInternetOpenA[LEN_OPCODES_HOOK_FUNCTION] = { 0 };
void HookInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
)
{
	Message("HookInternetOpenA called. Agent: %s\n", lpszAgent);
	exit(1);
}
