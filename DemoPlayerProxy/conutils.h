#ifndef __CONUTILS_H_
#define __CONUTILS_H_

#include <Windows.h>

namespace ConUtils
{
    void Init();
    void Free();

    void Log(const char *szText);
    void Log(const char *szText, WORD wAttributes);
    void Log(const WCHAR *szText);
    void Log(const WCHAR *szText, WORD wAttributes);
}

#endif