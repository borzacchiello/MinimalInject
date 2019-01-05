#pragma once

#define MAX_MEX_SIZE 512
#define LEN_OPCODES_HOOK_INSTRUCTION 18
#define LEN_OPCODES_HOOK_FUNCTION 7

typedef void(*funcpointer)(void *);

const LPCWSTR fname = L"c:\\Users\\luca\\INFO.txt";

void Message(LPCSTR fmt, ...);
void HookInstruction(funcpointer instructions_to_patch, funcpointer code_to_load, funcpointer return_address, unsigned char* old_data);
void HookFunction(funcpointer address_to_patch, funcpointer function_to_load, unsigned char* old_data);
void HookDynamicFunction(LPCSTR module_name, LPCSTR function_name, funcpointer function_to_load, unsigned char* old_data);
void RestoreData(LPVOID dst, LPVOID src, DWORD len);
void InitDebugFile();