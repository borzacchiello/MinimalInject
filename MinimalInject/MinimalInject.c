// Inject is a tool which injects an ordered list of shared libraries into the
// address space of a binary executable. The created process is initially
// suspended, and resumes execution once the ordered list of shared libraries
// have been loaded into its address space, and their respective DllMain
// functions have finished executing.
//
// Usage
//
//    $ inject EXE [DLL...]
//
// Examples
//
//    $ inject a.exe b.dll c.dll
//
// Order of execution:
//
//    1. Creates a suspended process of "a.exe".
//    2. Loads "b.dll" into the address space of "a.exe".
//    3. Executes the "DllMain" function of "b.dll".
//    4. Loads "c.dll" into the address space of "a.exe".
//    5. Executes the "DllMain" function of "d.dll".
//    6. Resumes execution of "a.exe".

#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>

#define MAX_MEX_LEN 512

static void GetFullPath(const char* path, char* fullPath) {
	if (!path) {
		fprintf(stderr, "Path has not been provided\n");
		exit(1);
	}

	if (!PathFileExistsA(path)) {
		fprintf(stderr, "Invalid path %s has been provided\n", path);
		exit(1);
	}

	if (!GetFullPathNameA(path, MAX_PATH, fullPath, NULL)) {
		fprintf(stderr, "Unable to get full path of %s\n", fullPath);
		exit(1);
	}
}

int main(int argc, char **argv) {
	int i, len;
	char *exe_path, *lib_path;
	char full_exe_path[MAX_PATH];
	char full_lib_path[MAX_PATH];
	char error[MAX_MEX_LEN] = { 0 };
	void *page;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE hThread;

	// Print usage.
	if (argc < 2) {
		fprintf(stderr, "Usage: inject EXE [DLL...]\n");
		fprintf(stderr, "Inject an ordered list of shared libraries into the address space of a binary executable.\n");
		return 1;
	}

	// Execute the process in suspended mode.
	exe_path = argv[1];
	GetFullPath(exe_path, full_exe_path);
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcessA(NULL, full_exe_path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		fprintf(stderr, "CreateProcess(\"%s\") failed; error code = 0x%08X\n", full_exe_path, GetLastError());
		return 1;
	}

	// Allocate a page in memory for the arguments of LoadLibrary.
	page = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (page == NULL) {
		fprintf(stderr, "VirtualAllocEx failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Inject the ordered list of shared libraries into the address space of the
	// process.
	for (i = 2; i < argc; i++) {
		// Verify path length.
		lib_path = argv[i];
		GetFullPath(lib_path, full_lib_path);
		len = strlen(full_lib_path) + 1;
		if (len > MAX_PATH) {
			fprintf(stderr, "path length (%d) exceeds MAX_PATH (%d).\n", len, MAX_PATH);
			return 1;
		}
		if (GetFileAttributesA(full_lib_path) == INVALID_FILE_ATTRIBUTES) {
			fprintf(stderr, "unable to locate library (%s).\n", full_lib_path);
			return 1;
		}

		// Write library path to the page used for LoadLibrary arguments.
		if (WriteProcessMemory(pi.hProcess, page, full_lib_path, len, NULL) == 0) {
			fprintf(stderr, "WriteProcessMemory failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Inject the shared library into the address space of the process,
		// through a call to LoadLibrary.
		hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, page, 0, NULL);
		if (hThread == NULL) {
			fprintf(stderr, "CreateRemoteThread failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Wait for DllMain to return.
		if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
			fprintf(stderr, "WaitForSingleObject failed; error code = 0x%08X\n", GetLastError());
			return 1;
		}

		// Cleanup.
		CloseHandle(hThread);
	}

	// Resume the execution of the process, once all libraries have been injected
	// into its address space.
	if (ResumeThread(pi.hThread) == -1) {
		fprintf(stderr, "ResumeThread failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	if (WaitForSingleObject(pi.hThread, INFINITE) == WAIT_FAILED) {
		fprintf(stderr, "WaitForSingleObject failed; error code = 0x%08X\n", GetLastError());
		return 1;
	}

	// Cleanup.
	VirtualFreeEx(pi.hProcess, page, MAX_PATH, MEM_RELEASE);
	CloseHandle(pi.hProcess);
	return 0;
}