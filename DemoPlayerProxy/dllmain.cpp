// dllmain.cpp : Defines the entry point for the DLL application.
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>

#include "conutils.h"
#include "hooks.h"

typedef int (__cdecl *CreateInterface_t)(const char *name, int version);

struct demoplayer_dll
{
	HMODULE hDll;
	CreateInterface_t CreateInterface;
} demoplayer;

int FakeCreateInterface(const char *name, int version)
{
	int result = demoplayer.CreateInterface(name, version);

	char temp[1024];
	sprintf(temp, "Engine call: CreateInterface(\"%s\", %d) => %x\n", name, version, result);
	ConUtils::Log(temp, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	return result;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	WCHAR filename[MAX_PATH];
	WCHAR original_dll[MAX_PATH];

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		ConUtils::Init();

		GetModuleFileName(hModule, filename, sizeof(filename));
		wcsncpy(original_dll, filename, wcslen(filename) - 4);
		wcsncpy(original_dll + wcslen(filename) - 4, L"_original.dll\0", 14);

		demoplayer.hDll = LoadLibrary(original_dll);
		if (!demoplayer.hDll)
		{
			MessageBox(NULL, L"Could not load the original DemoPlayer DLL!", L"Error", MB_OK);
			ExitProcess(0);
		}
		ConUtils::Log("Loaded DemoPlayer_original.dll.\n");

		demoplayer.CreateInterface = (CreateInterface_t) GetProcAddress(demoplayer.hDll, "CreateInterface");
		ConUtils::Log("Obtained the CreateInterface address.\n");

		Hooks::Init();

		break;

	case DLL_PROCESS_DETACH:
		Hooks::Free();

		FreeLibrary(demoplayer.hDll);

		ConUtils::Log("Unloaded DemoPlayer_original.dll.\n");
		ConUtils::Free();
		break;
	}
	return TRUE;
}

