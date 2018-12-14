// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include "Util.h"
#include "ThreadLibraryHooks.h"

#include <iostream>

BOOL executed = false;

#define ADDRESS_GET_EXPLORER_PID 0x402550
#define ADDRESS_SKIP_REMOTE_THREAD 0x402448
#define ADDRESS_SKIP_REMOTE_THREAD_RETURN 0x402472
#define ADDRESS_VIRTUAL_ALLOC 0x40138A

#define ADDRESS_HOOK_THREAD 0x4013F7
#define OFFSET_THREAD_MAIN_LOOP 0x4A9

unsigned long address_t1;

// HOOKS *******************************************************************************************

// return PID of enfal instead of PID of explorer.exe
unsigned char oldGetExplorerPid[7] = { 0 };
static DWORD HookGetExplorerPid()
{
	Message("HookGetPid triggered\n");
	RestoreData((LPVOID)ADDRESS_GET_EXPLORER_PID, oldGetExplorerPid, 7);
	return GetCurrentProcessId();
}

// avoid SetReg
unsigned char oldSetReg[7] = { 0 };
static LSTATUS HookSetReg()
{
	Message("HookSetReg triggered\n");
	RestoreData((LPVOID)GetProcAddress(GetModuleHandleA("advapi32"), "RegSetValueExA"), oldSetReg, 7);
	return 1;
}

// avoid CloseReg (crash otherwise)
unsigned char oldCloseReg[7] = { 0 };
static LSTATUS HookCloseReg()
{
	Message("HookCloseReg triggered\n");
	RestoreData((LPVOID)GetProcAddress(GetModuleHandleA("advapi32"), "RegCloseKey"), oldCloseReg, 7);
	return 1;
}

// create only the first thread (the interesting one) and put the main thread to sleep
unsigned char oldSkipRemote[18] = { 0 };
static void SkipOtherCreateRemoteThread(unsigned long eax, unsigned long ebx, unsigned long ecx, 
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("SkipOtherCreateRemoteThread triggered\n");
	RestoreData((LPVOID)ADDRESS_SKIP_REMOTE_THREAD, oldSkipRemote, 18);
	Sleep(1000 * 3600); // sleep for 1 hour
}

// intercept the address of the function where the thread will start
unsigned char oldInterceptVirtualAlloc[18] = { 0 };
static void InterceptVirtualAlloc(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	address_t1 = eax;

	Message("InterceptVirtualAlloc triggered, ADDRESS: %08x\n", address_t1);
	RestoreData((LPVOID)ADDRESS_VIRTUAL_ALLOC, oldInterceptVirtualAlloc, 18);
}

// hook the thread function
unsigned char oldThreadFunction[18] = { 0 };
static void InterceptThreadFunction(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("Thread function triggered\n");
	RestoreData((LPVOID)address_t1, oldThreadFunction, 18);
}

unsigned char oldThreadInitializationFinished[18] = { 0 };
static void ThreadInitializationFinished(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("Thread initialization phase finished. Entering the main loop. Hooking library functions.\n");
	RestoreData((LPVOID)(address_t1 + OFFSET_THREAD_MAIN_LOOP), oldThreadInitializationFinished, 18);
	HookDynamicFunction("wininet", "InternetOpenA" , (funcpointer)&HookInternetOpenA, oldHookInternetOpenA);
}

// set the hooks of the thread function (using the address leaked by InterceptVirtualAlloc)
unsigned char oldWriteThreadHook[18] = { 0 };
static void WriteThreadHook(unsigned long eax, unsigned long ebx, unsigned long ecx,
	unsigned long edx, unsigned long edi, unsigned long esi)
{
	Message("Writing on thread function data\n");
	RestoreData((LPVOID)ADDRESS_HOOK_THREAD, oldWriteThreadHook, 18);
	HookInstruction((funcpointer)address_t1, (funcpointer)&InterceptThreadFunction,
		(funcpointer)address_t1, oldThreadFunction);
	HookInstruction((funcpointer)(address_t1+OFFSET_THREAD_MAIN_LOOP), (funcpointer)&ThreadInitializationFinished,
		(funcpointer)(address_t1+OFFSET_THREAD_MAIN_LOOP), oldThreadInitializationFinished);

}

// *************************************************************************************************


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	if (!executed) {
		// Create a file with the given information...
		HANDLE debug_file = CreateFile(fname, // file to be opened
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
		HookInstruction((funcpointer)ADDRESS_HOOK_THREAD, (funcpointer)&WriteThreadHook,
			(funcpointer)ADDRESS_HOOK_THREAD, oldWriteThreadHook);
		HookDynamicFunction("advapi32", "RegSetValueExA", (funcpointer)&HookSetReg, oldSetReg);
		HookDynamicFunction("advapi32", "RegCloseKey", (funcpointer)&HookCloseReg, oldCloseReg);
		Message("Patch completed\n");
		executed = true;
	}

	return true;
}
