// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "Util.h"

BOOL executed = FALSE;

unsigned char OldWrapperLoadLibraryA[LEN_OPCODES_HOOK_FUNCTION];
HMODULE WINAPI WrapperLoadLibraryA(
	LPCSTR lpLibFileName
)
{
	funcpointer OldLoadLibraryA = (funcpointer)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
	RestoreData((LPVOID)OldLoadLibraryA, OldWrapperLoadLibraryA, LEN_OPCODES_HOOK_FUNCTION);

	Message("Intercepted LoadLibraryA(%s)\n", lpLibFileName);
	HMODULE ris = LoadLibraryA(lpLibFileName);

	HookFunction(OldLoadLibraryA, (funcpointer)&WrapperLoadLibraryA, OldWrapperLoadLibraryA);
	return ris;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (!executed) {
		InitDebugFile();
		executed = TRUE;
		Message("%x\n", &WrapperLoadLibraryA);
		HookDynamicFunction("kernel32", "LoadLibraryA", (funcpointer)&WrapperLoadLibraryA, OldWrapperLoadLibraryA);
	}
	return TRUE;
}

