// dllmain.cpp : Definisce il punto di ingresso per l'applicazione DLL.
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HANDLE hFile;

	LPCWSTR fname = L"c:\\Users\\luca\\a.txt";

	// Create a file with the given information...
	hFile = CreateFile(fname, // file to be opened
		GENERIC_WRITE, // open for writing
		FILE_SHARE_WRITE, // share for writing
		NULL, // default security
		CREATE_ALWAYS, // create new file only
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | SECURITY_IMPERSONATION,
		// normal file archive and impersonate client
		NULL); // no attr. template
	CloseHandle(hFile);
    return TRUE;
}

