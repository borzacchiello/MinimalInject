// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"
#include <iostream>

#define ADDRESS 0x401080

typedef void(*funcpointer)(void *);

BOOL executed = false;

static void patch(funcpointer address_to_patch, funcpointer function_to_load)
{
	std::cout << std::hex << ADDRESS << "\n";
	std::cout << std::hex << function_to_load << "\n";
	for (int i = 0; i < 7; ++i)
		std::cout << std::hex << (int)*((unsigned char*)address_to_patch + i) << " ";

	std::cout << "\n";	unsigned char opcodes[] = {												// MOV EAX, $ADDRESS_TO_PATCH
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
		std::cerr << "VirtualProtect failed\n";
		exit(1);
	}

	/*if (!memcpy((void*)address_to_patch, opcodes, len_opcodes)) {
		std::cerr << "memcpy failed\n";
		exit(1);
	}*/

	//BOOL WINAPI WriteProcessMemory(
	//	_In_  HANDLE  hProcess,
	//	_In_  LPVOID  lpBaseAddress,
	//	_In_  LPCVOID lpBuffer,
	//	_In_  SIZE_T  nSize,
	//	_Out_ SIZE_T  *lpNumberOfBytesWritten
	//);

	SIZE_T bytes_written;

	if (!WriteProcessMemory(
		GetCurrentProcess(),
		(LPVOID)address_to_patch,
		(LPVOID)opcodes,
		len_opcodes,
		&bytes_written
	)) {
		std::cerr << "WriteProcessMemory failed\n";
		exit(1);
	}
	else if (bytes_written != len_opcodes) {
		std::cerr << "written too few bytes\n";
		exit(1);
	}

	// std::cout << std::hex << (int)*((unsigned char*)address_to_patch) << std::hex << (int)*((unsigned char*)address_to_patch + 1) << "\n";
	for (int i = 0; i < len_opcodes; ++i)
		std::cout << std::hex << (int)*((unsigned char*)address_to_patch+i) << " ";
	std::cout << "\n";
}

static void f() 
{
	std::cout << "HACKED\n";
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	if (!executed) {
		std::cout << "PLING\n";
		f();
		patch((funcpointer)ADDRESS, (funcpointer)&f);
		executed = true;
	}
	return true;
}
