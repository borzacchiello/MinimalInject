#include "stdafx.h"
#include "Util.h"
#include "trampoline.h"

void Message(LPCSTR fmt, ...) {
	CHAR message[MAX_MEX_SIZE] = { 0 };
	va_list args;

	va_start(args, fmt);
	vsnprintf(message, MAX_MEX_SIZE, fmt, args);
	va_end(args);

	HANDLE debug_file = CreateFile(
		fname,
		FILE_APPEND_DATA,
		FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0);

	DWORD bytesWritten;
	WriteFile(debug_file, "[ENFAL-hook] ", 13, &bytesWritten, NULL);
	WriteFile(debug_file, message, strlen(message), &bytesWritten, NULL);
	CloseHandle(debug_file);
}

void InitDebugFile()
{
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
}

void HookInstruction(funcpointer instructions_to_patch, funcpointer code_to_load, funcpointer return_address, unsigned char* old_data)
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

void HookFunction(funcpointer address_to_patch, funcpointer function_to_load, unsigned char* old_data)
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

void HookDynamicFunction(LPCSTR module_name, LPCSTR function_name, funcpointer function_to_load, unsigned char* old_data)
{
	funcpointer f = (funcpointer)GetProcAddress(GetModuleHandleA(module_name), function_name);
	if (!f) {
		Message("GetProcAddress failed\n");
		exit(1);
	}
	HookFunction(f, function_to_load, old_data);
}

// restore old opcodes
void RestoreData(LPVOID dst, LPVOID src, DWORD len)
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