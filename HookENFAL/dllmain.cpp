// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"

#include <iostream>

LPCWSTR fname = L"c:\\Users\\luca\\ENFAL-INFO.txt";
HANDLE debug_file;
BOOL executed = false;

#define ADDRESS_GET_EXPLORER_PID 0x402550

typedef void(*funcpointer)(void *);

// UTIL ********************************************************************************************

static void Message(const char* mex)
{
	debug_file = CreateFile(
		fname, 
		FILE_APPEND_DATA, 
		FILE_SHARE_WRITE, 
		0, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		0);

	DWORD bytesWritten;
	WriteFile(debug_file, mex, strlen(mex), &bytesWritten, NULL);
	CloseHandle(debug_file);
}

static void HookFunction(funcpointer address_to_patch, funcpointer function_to_load)
{
	DWORD bytes_written;

	unsigned char opcodes[] = {										// MOV EAX, $ADDRESS_TO_PATCH
		0xB8,														// JMP EAX
		(unsigned char)(((unsigned long)function_to_load)),
		(unsigned char)(((unsigned long)function_to_load) >> 8),
		(unsigned char)(((unsigned long)function_to_load) >> 16),
		(unsigned char)(((unsigned long)function_to_load) >> 24),
		0xFF,
		0xE0
	};
	SIZE_T len_opcodes = sizeof(opcodes);

	DWORD dwProtect;
	if (!VirtualProtect(address_to_patch, len_opcodes, PAGE_EXECUTE_READWRITE, &dwProtect)) {
		Message("VirtualProtect failed\n");
		exit(1);
	}

	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)address_to_patch,
		(LPVOID)opcodes,
		len_opcodes,
		&bytes_written
	)) {
		Message("WriteProcessMemory failed\n");
		exit(1);
	}
	else if (bytes_written != len_opcodes) {
		Message("written too few bytes\n");
		exit(1);
	}

	if (!FlushInstructionCache(
		GetCurrentProcess(),
		address_to_patch,
		len_opcodes
	)) {
		Message("FlushInstructionCache failed\n");
		exit(1);
	}
}

static void HookDynamicFunction(LPCSTR module_name, LPCSTR function_name, funcpointer function_to_load) 
{
	funcpointer f = (funcpointer)GetProcAddress(GetModuleHandleA(module_name), function_name);
	if ( !f ) {
		Message("GetProcAddress failed\n");
		exit(1);
	}
	HookFunction(f, function_to_load);
}

// *************************************************************************************************
// HOOKS *******************************************************************************************

static DWORD HookGetExplorerPid()
{
	Message("HookGetPid triggered\n");
	return GetCurrentProcessId();
}

static LSTATUS HookSetReg()
{
	Message("HookSetReg triggered\n");
	return 1;
}

// *************************************************************************************************


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	if (!executed) {
		// Create a file with the given information...
		debug_file = CreateFile(fname, // file to be opened
			GENERIC_WRITE, // open for writing
			FILE_SHARE_WRITE, // share for writing
			NULL, // default security
			CREATE_ALWAYS, // create new file only
			FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | SECURITY_IMPERSONATION,
			// normal file archive and impersonate client
			NULL); // no attr. template
		CloseHandle(debug_file);

		Message("File initialization completed\n");
		HookFunction((funcpointer)ADDRESS_GET_EXPLORER_PID, (funcpointer)&HookGetExplorerPid);
		HookDynamicFunction("advapi32", "RegSetValueExA", (funcpointer)&HookSetReg);
		Message("Patch completed\n");
		executed = true;
	}

	return true;
}
