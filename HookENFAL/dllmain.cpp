// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "trampoline.h"

#include <iostream>

LPCWSTR fname = L"c:\\Users\\luca\\ENFAL-INFO.txt";
HANDLE debug_file;
BOOL executed = false;

#define ADDRESS_GET_EXPLORER_PID 0x402550
#define ADDRESS_SKIP_REMOTE_THREAD 0x402448
#define ADDRESS_SKIP_REMOTE_THREAD_RETURN 0x402472
#define ADDRESS_VIRTUAL_ALLOC 0x40138A

unsigned long address_t1;

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


static void HookInstruction(funcpointer instructions_to_patch, funcpointer code_to_load, funcpointer return_address, unsigned char* old_data)
{
	DWORD bytes_written;

	unsigned char opcodes[] = {									// push eax
	0x50,														// mov eax, Trampoline
	0xB8,														// push return_address
	(unsigned char)(((unsigned long)&trampoline)),				// push code_to_load
	(unsigned char)(((unsigned long)&trampoline) >> 8),			// jmp eax
	(unsigned char)(((unsigned long)&trampoline) >> 16),
	(unsigned char)(((unsigned long)&trampoline) >> 24),
	0x68,
	(unsigned char)(((unsigned long)return_address)),
	(unsigned char)(((unsigned long)return_address) >> 8),
	(unsigned char)(((unsigned long)return_address) >> 16),
	(unsigned char)(((unsigned long)return_address) >> 24),
	0x68,
	(unsigned char)(((unsigned long)code_to_load)),
	(unsigned char)(((unsigned long)code_to_load) >> 8),
	(unsigned char)(((unsigned long)code_to_load) >> 16),
	(unsigned char)(((unsigned long)code_to_load) >> 24),
	0xFF,
	0xE0
	};
	SIZE_T len_opcodes = sizeof(opcodes);

	DWORD dwProtect;
	if (!VirtualProtect(instructions_to_patch, len_opcodes, PAGE_EXECUTE_READWRITE, &dwProtect)) {
		Message("VirtualProtect failed\n");
		exit(1);
	}

	// Save old opcodes
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)old_data,
		(LPVOID)instructions_to_patch,
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

	// Write new opcodes
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)instructions_to_patch,
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
		instructions_to_patch,
		len_opcodes
	)) {
		Message("FlushInstructionCache failed\n");
		exit(1);
	}

}

static void HookFunction(funcpointer address_to_patch, funcpointer function_to_load, unsigned char* old_data)
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

	// Save old opcodes
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)old_data,
		(LPVOID)address_to_patch,
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

	// Write new opcodes
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

static void HookDynamicFunction(LPCSTR module_name, LPCSTR function_name, funcpointer function_to_load, unsigned char* old_data) 
{
	funcpointer f = (funcpointer)GetProcAddress(GetModuleHandleA(module_name), function_name);
	if ( !f ) {
		Message("GetProcAddress failed\n");
		exit(1);
	}
	HookFunction(f, function_to_load, old_data);
}

// restore old opcodes
static void RestoreData(LPVOID dst, LPVOID src, DWORD len)
{
	DWORD bytes_written;
	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)dst,
		(LPVOID)src,
		len,
		&bytes_written
	)) {
		Message("WriteProcessMemory failed\n");
		exit(1);
	}
	else if (bytes_written != len) {
		Message("written too few bytes\n");
		exit(1);
	}

	if (!FlushInstructionCache(
		GetCurrentProcess(),
		dst,
		len
	)) {
		Message("FlushInstructionCache failed\n");
		exit(1);
	}
}

// *************************************************************************************************
// HOOKS *******************************************************************************************

unsigned char oldGetExplorerPid[7] = { 0 };
static DWORD HookGetExplorerPid()
{
	Message("HookGetPid triggered\n");
	RestoreData((LPVOID)ADDRESS_GET_EXPLORER_PID, oldGetExplorerPid, 7);
	return GetCurrentProcessId();
}

unsigned char oldSetReg[7] = { 0 };
static LSTATUS HookSetReg()
{
	Message("HookSetReg triggered\n");
	RestoreData((LPVOID)GetProcAddress(GetModuleHandleA("advapi32"), "RegSetValueExA"), oldSetReg, 7);
	return 1;
}

unsigned char oldCloseReg[7] = { 0 };
static LSTATUS HookCloseReg()
{
	Message("HookCloseReg triggered\n");
	RestoreData((LPVOID)GetProcAddress(GetModuleHandleA("advapi32"), "RegCloseKey"), oldCloseReg, 7);
	return 1;
}

unsigned char oldSkipRemote[18] = { 0 };
static void SkipOtherCreateRemoteThread(unsigned long eax, unsigned long ebx, unsigned long ecx, 
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("SkipOtherCreateRemoteThread triggered\n");
	RestoreData((LPVOID)ADDRESS_SKIP_REMOTE_THREAD, oldSkipRemote, 18);
	Sleep(1000 * 3600); // sleep for 1 hour
}

unsigned char oldInterceptVirtualAlloc[18] = { 0 };
static void InterceptVirtualAlloc(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	address_t1 = eax;

	char str[10]; str[9] = '\0';
	sprintf_s(str, "%08x\n", address_t1);
	Message("InterceptVirtualAlloc triggered\n");
	Message("ADDRESS: ");
	Message(str);

	RestoreData((LPVOID)ADDRESS_VIRTUAL_ALLOC, oldInterceptVirtualAlloc, 18);
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
		HookFunction((funcpointer)ADDRESS_GET_EXPLORER_PID, (funcpointer)&HookGetExplorerPid, oldGetExplorerPid);
		HookInstruction((funcpointer)ADDRESS_SKIP_REMOTE_THREAD, (funcpointer)&SkipOtherCreateRemoteThread, 
			(funcpointer)ADDRESS_SKIP_REMOTE_THREAD_RETURN, oldSkipRemote);
		HookInstruction((funcpointer)ADDRESS_VIRTUAL_ALLOC, (funcpointer)&InterceptVirtualAlloc, 
			(funcpointer)ADDRESS_VIRTUAL_ALLOC, oldInterceptVirtualAlloc);
		HookDynamicFunction("advapi32", "RegSetValueExA", (funcpointer)&HookSetReg, oldSetReg);
		HookDynamicFunction("advapi32", "RegCloseKey", (funcpointer)&HookCloseReg, oldCloseReg);
		Message("Patch completed\n");
		executed = true;
	}

	return true;
}
