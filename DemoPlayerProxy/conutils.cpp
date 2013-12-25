#include "conutils.h"

namespace ConUtils
{
	HANDLE hConsoleOutput;
	WORD wStandartAttributes;

	void Init()
	{
		AllocConsole();
		hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);

		CONSOLE_SCREEN_BUFFER_INFO coninfo;
		GetConsoleScreenBufferInfo(hConsoleOutput, &coninfo);
		wStandartAttributes = coninfo.wAttributes;
		coninfo.dwSize.X = 150;
		coninfo.dwSize.Y = 500;
		SetConsoleScreenBufferSize(hConsoleOutput, coninfo.dwSize);

		SetConsoleTitle(L"Bunnymod XT Debug Console");

		ShowWindow(GetConsoleWindow(), SW_MAXIMIZE);
		ShowWindow(GetConsoleWindow(), SW_MINIMIZE);
	}

	void Free()
	{
		FreeConsole();
	}

	void Log(const char *szText)
	{
		WriteConsoleA(hConsoleOutput, szText, strlen(szText), NULL, NULL);
	}

	void Log(const char *szText, WORD wAttributes)
	{
		SetConsoleTextAttribute(hConsoleOutput, wAttributes);
		WriteConsoleA(hConsoleOutput, szText, strlen(szText), NULL, NULL);
		SetConsoleTextAttribute(hConsoleOutput, wStandartAttributes);
	}

	void Log(const WCHAR *szText)
	{
		WriteConsole(hConsoleOutput, szText, wcslen(szText), NULL, NULL);
	}

	void Log(const WCHAR *szText, WORD wAttributes)
	{
		SetConsoleTextAttribute(hConsoleOutput, wAttributes);
		WriteConsole(hConsoleOutput, szText, wcslen(szText), NULL, NULL);
		SetConsoleTextAttribute(hConsoleOutput, wStandartAttributes);
	}
}