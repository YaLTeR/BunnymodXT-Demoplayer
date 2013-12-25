#ifndef __HOOKS_H_
#define __HOOKS_H_

#include <Windows.h>
#include "HLSDK\util_vector.h"
#include "HLSDK\cdll_int.h"
#include "HLSDK\eiface.h"
#include "HLSDK\progdefs.h"

typedef unsigned char byte;

typedef struct
{
    HMODULE hDll;
    size_t dwStart;
    size_t dwLength;

    DWORD dwBhopCap;
    byte bBhopCapType;

    DWORD dwAutojump;
    BYTE pbAutojumpOrigBytes[6];

    cl_enginefunc_t *pEngfuncs;
} client_dll_t;

typedef struct
{
    HMODULE hDll;
    size_t dwStart;
    size_t dwLength;

    DWORD dwBhopCap;
    byte bBhopCapType;

    DWORD dwAutojump;
    BYTE pbAutojumpOrigBytes[6];

    enginefuncs_t *pEngfuncs;
} server_dll_t;

namespace Hooks
{
    namespace Internal
    {
        HMODULE WINAPI NewLoadLibraryA(LPCSTR lpLibFileName);
        HMODULE WINAPI NewLoadLibraryW(LPCWSTR lpLibFileName);

        void __stdcall SERVER_NewGiveFnptrsToDll(enginefuncs_t* pengfuncsFromEngine, globalvars_t *pGlobals);
    }

    namespace Client
    {
        void HookBhopCap();
        void HookAutojump();
        void HookEngfuncs();

        void ConCmd_BhopCap();
        void ConCmd_Autojump();
    }

    namespace Server
    {
        void HookBhopCap();
        void HookAutojump();

        void ConCmd_BhopCap();
        void ConCmd_Autojump();
    }

    void Init();
    void Free();

    void HookClientDLL();
    void HookServerDLL();

    void UnhookServerDLL();
}

#endif