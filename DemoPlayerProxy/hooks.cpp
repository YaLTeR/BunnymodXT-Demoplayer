#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include "detours.h"

#include "hooks.h"
#include "conutils.h"
#include "memutils.h"

#pragma comment( lib, "detours.lib" )

namespace Hooks
{
    client_dll_t client_dll;
    server_dll_t server_dll;

    namespace Internal
    {
        static HMODULE (WINAPI *OriginalLoadLibraryW) (LPCWSTR lpLibFileName)	= LoadLibraryW;
        static HMODULE (WINAPI *OriginalLoadLibraryA) (LPCSTR lpLibFileName)	= LoadLibraryA;

        static void (__stdcall *SERVER_OriginalGiveFnptrsToDll) (enginefuncs_t* pengfuncsFromEngine, globalvars_t *pGlobals) = NULL;

        HMODULE WINAPI NewLoadLibraryA(LPCSTR lpLibFileName)
        {
            HMODULE result = OriginalLoadLibraryA(lpLibFileName);

            char temp[1024];
            sprintf(temp, "Engine call: LoadLibraryA(\"%s\") => %x\n", lpLibFileName, result);
            ConUtils::Log(temp, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            if ( !client_dll.hDll && strstr(lpLibFileName, "client.dll") )
            {
                if ( result )
                {
                    client_dll.hDll = result;
                    Hooks::HookClientDLL();
                }
            }

            if ( !server_dll.hDll && (strstr(lpLibFileName, "hl.dll") || strstr(lpLibFileName, "opfor.dll") || strstr(lpLibFileName, "cz.dll") || strstr(lpLibFileName, "ag.dll")) )
            {
                if ( result )
                {
                    server_dll.hDll = result;

                    Hooks::UnhookServerDLL();
                    Hooks::HookServerDLL();
                }
            }

            return result;
        }

        HMODULE WINAPI NewLoadLibraryW(LPCWSTR lpLibFileName)
        {
            HMODULE result = OriginalLoadLibraryW(lpLibFileName);

            WCHAR temp[1024];
            wsprintf(temp, L"Engine call: LoadLibraryW(\"%s\") => %x\n", lpLibFileName, result);
            ConUtils::Log(temp, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            if ( !client_dll.hDll && wcsstr(lpLibFileName, L"client.dll") )
            {
                if ( result )
                {
                    client_dll.hDll = result;
                    Hooks::HookClientDLL();
                }
            }

            if ( !server_dll.hDll && (wcsstr(lpLibFileName, L"hl.dll") || wcsstr(lpLibFileName, L"opfor.dll") || wcsstr(lpLibFileName, L"cz.dll") || wcsstr(lpLibFileName, L"ag.dll")) )
            {
                if ( result )
                {
                    server_dll.hDll = result;

                    Hooks::UnhookServerDLL();
                    Hooks::HookServerDLL();
                }
            }

            return result;
        }

        void __stdcall SERVER_NewGiveFnptrsToDll(enginefuncs_t* pengfuncsFromEngine, globalvars_t *pGlobals)
        {
            WCHAR temp[1024];
            wsprintf(temp, L"Engine call: GiveFnptrsToDll(%x, %x)\n", pengfuncsFromEngine, pGlobals);
            ConUtils::Log(temp, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            server_dll.pEngfuncs = pengfuncsFromEngine;
            SERVER_OriginalGiveFnptrsToDll(pengfuncsFromEngine, pGlobals);

            Hooks::Server::HookBhopCap();
            //Hooks::Server::HookAutojump();
        }
    }

    namespace Client
    {
        void HookBhopCap()
        {
            client_dll.bBhopCapType = 0;
            client_dll.dwBhopCap = NULL;

            byte bhopcap_type = 0;

            DWORD dwPreventMegaBunnyJumpAddr = MemUtils::FindPattern(client_dll.dwStart, client_dll.dwLength, (PBYTE) "\x55\x8B\xEC\x83\xEC\x0C\xA1\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD8\x88", "xxxxxxx????xx????xx");
            if ( !dwPreventMegaBunnyJumpAddr )
            {
                dwPreventMegaBunnyJumpAddr = MemUtils::FindPattern(client_dll.dwStart, client_dll.dwLength, (PBYTE) "\x51\x8B\x0D\x00\x00\x00\x00\xD9\x81\x00\x00\x00\x00\xD8\x0D", "xxx????xx????xx");
                if ( !dwPreventMegaBunnyJumpAddr )
                {
                    ConUtils::Log("[client dll] Could not find the PreventMegaBunnyJump() function!\n", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    return;
                }
                else
                {
                    bhopcap_type = 1;
                }
            }

            WCHAR temp[256];
            wsprintf(temp, L"[client dll] PreventMegaBunnyJump() is located at: %x\n", dwPreventMegaBunnyJumpAddr);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            if (bhopcap_type == 0)
            {
                dwPreventMegaBunnyJumpAddr += 37;
                if ( (*(BYTE*)dwPreventMegaBunnyJumpAddr == 0x74) && (*(BYTE*) (dwPreventMegaBunnyJumpAddr + 1) == 0x02) )
                {
                    client_dll.dwBhopCap = dwPreventMegaBunnyJumpAddr;
                    client_dll.bBhopCapType = bhopcap_type;
                    MemUtils::ReplaceBytes(client_dll.dwBhopCap, 2, (PBYTE) "\x90\x90");

                    if (client_dll.pEngfuncs)
                    {
                        client_dll.pEngfuncs->pfnAddCommand("y_cl_bhopcap", ConCmd_BhopCap);
                    }

                    ConUtils::Log("[client dll] The bhop cap was successfully stripped!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                }
                else
                {
                    ConUtils::Log("[client dll] Wrong bytes at PreventMegaBunnyJump()! Bhop cap remover disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                }
            }
            else if (bhopcap_type == 1)
            {
                dwPreventMegaBunnyJumpAddr += 34;
                if ( *(BYTE*)dwPreventMegaBunnyJumpAddr == 0x7B )
                {
                    client_dll.dwBhopCap = dwPreventMegaBunnyJumpAddr;
                    client_dll.bBhopCapType = bhopcap_type;
                    MemUtils::ReplaceBytes(client_dll.dwBhopCap, 1, (PBYTE) "\xEB");

                    if (client_dll.pEngfuncs)
                    {
                        client_dll.pEngfuncs->pfnAddCommand("y_cl_bhopcap", ConCmd_BhopCap);
                    }

                    ConUtils::Log("[client dll] The bhop cap was successfully stripped!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                }
                else
                {
                    ConUtils::Log("[client dll] Wrong bytes at PreventMegaBunnyJump()! Bhop cap remover disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                }
            }
        }

        void HookAutojump()
        {
            client_dll.dwAutojump = NULL;
            memset(client_dll.pbAutojumpOrigBytes, 0, sizeof(client_dll.pbAutojumpOrigBytes));

            DWORD dwAutojumpAddr = MemUtils::FindPattern(client_dll.dwStart, client_dll.dwLength, (PBYTE) "\x8B\x81\x00\x00\x00\x00\xBB\x02\x00\x00\x00\x3B\xC3", "xx????xxxxxxx");
            if ( !dwAutojumpAddr )
            {
                ConUtils::Log("[client dll] Could not find the autojump check offset!\n", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                return;
            }

            WCHAR temp[256];
            wsprintf(temp, L"[client dll] The autojump check is located at: %x\n", dwAutojumpAddr);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            dwAutojumpAddr += 326;
            if ( (*(BYTE *) dwAutojumpAddr == 0x0F) && (*(BYTE *) (dwAutojumpAddr + 1) == 0x85) )
            {
                client_dll.dwAutojump = dwAutojumpAddr;
                memcpy(client_dll.pbAutojumpOrigBytes, (void *) dwAutojumpAddr, sizeof(client_dll.pbAutojumpOrigBytes));

                MemUtils::ReplaceBytes(client_dll.dwAutojump, 6, (PBYTE) "\x90\x90\x90\x90\x90\x90");

                if (client_dll.pEngfuncs)
                {
                    client_dll.pEngfuncs->pfnAddCommand("y_cl_autojump", ConCmd_Autojump);
                }

                ConUtils::Log("[client dll] Autojump was enabled!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            }
            else
            {
                ConUtils::Log("[client dll] Wrong bytes at the autojump offset! Autojump disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            }
        }

        void HookEngfuncs()
        {
            client_dll.pEngfuncs = NULL;

            DWORD dwVoiceiconStringAddr = MemUtils::FindPattern(client_dll.dwStart, client_dll.dwLength, (PBYTE) "sprites/voiceicon.spr", "xxxxxxxxxxxxxxxxxxxxx");
            if ( !dwVoiceiconStringAddr )
            {
                ConUtils::Log("[client dll] Could not find \"sprites/voiceicon.spr\"! Disabling engfuncs hooks...\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                return;
            }

            WCHAR temp[256];
            wsprintf(temp, L"[client dll] \"sprites/voiceicon.spr\" is located at: %x\n", dwVoiceiconStringAddr);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            byte pattern[14];
            pattern[0] = '\x68';
            *(DWORD *) (pattern + 1) = dwVoiceiconStringAddr;
            pattern[5] = '\xFF';
            pattern[6] = '\x15';
            pattern[11] = '\x83';
            pattern[12] = '\xC4';
            pattern[13] = '\x04';

            DWORD dwEngfuncsCallAddr = MemUtils::FindPattern(client_dll.dwStart, client_dll.dwLength, pattern, "xxxxxxx????xxx");
            if ( !dwEngfuncsCallAddr )
            {
                ConUtils::Log("[client dll] Could not find the engfuncs call address! Engfuncs hooks disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                return;
            }

            client_dll.pEngfuncs = *(cl_enginefunc_t **) (dwEngfuncsCallAddr + 7);

            wsprintf(temp, L"[client dll] Engfuncs are located at: %x\n", client_dll.pEngfuncs);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }

        void ConCmd_BhopCap()
        {
            if ( client_dll.pEngfuncs->Cmd_Argc() == 1 )
            {
                switch (client_dll.bBhopCapType)
                {
                case 0:
                    if ( *(BYTE *) client_dll.dwBhopCap == 0x74 )
                    {
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is currently enabled.\n");
                    }
                    else
                    {
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is currently disabled.\n");
                    }

                    break;

                case 1:
                    if ( *(BYTE *) client_dll.dwBhopCap == 0x7B )
                    {
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is currently enabled.\n");
                    }
                    else
                    {
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is currently disabled.\n");
                    }

                    break;
                }
            }
            else if ( client_dll.pEngfuncs->Cmd_Argc() > 1 )
            {
                int arg;
                sscanf(client_dll.pEngfuncs->Cmd_Argv(1), "%d", &arg);

                switch (client_dll.bBhopCapType)
                {
                case 0:
                    if (arg == 0)
                    {
                        MemUtils::ReplaceBytes(client_dll.dwBhopCap, 2, (PBYTE) "\x90\x90");
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is now disabled.\n");
                    }
                    else
                    {
                        MemUtils::ReplaceBytes(client_dll.dwBhopCap, 2, (PBYTE) "\x74\x02");
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is now enabled.\n");
                    }

                    break;

                case 1:
                    if (arg == 0)
                    {
                        MemUtils::ReplaceBytes(client_dll.dwBhopCap, 1, (PBYTE) "\xEB");
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is now disabled.\n");
                    }
                    else
                    {
                        MemUtils::ReplaceBytes(client_dll.dwBhopCap, 1, (PBYTE) "\x7B");
                        client_dll.pEngfuncs->Con_Printf("The bhop cap is now enabled.\n");
                    }

                    break;
                }
            }
        }

        void ConCmd_Autojump()
        {
            if ( client_dll.pEngfuncs->Cmd_Argc() == 1 )
            {
                if ( *(BYTE *) client_dll.dwAutojump == 0x0F )
                {
                    client_dll.pEngfuncs->Con_Printf("Autojump is currently disabled.\n");
                }
                else
                {
                    client_dll.pEngfuncs->Con_Printf("Autojump is currently enabled.\n");
                }
            }
            else if ( client_dll.pEngfuncs->Cmd_Argc() > 1 )
            {
                int arg;
                sscanf(client_dll.pEngfuncs->Cmd_Argv(1), "%d", &arg);

                if (arg == 0)
                {
                    MemUtils::ReplaceBytes(client_dll.dwAutojump, sizeof(client_dll.pbAutojumpOrigBytes), client_dll.pbAutojumpOrigBytes);
                    client_dll.pEngfuncs->Con_Printf("Autojump is now disabled.\n");
                }
                else
                {
                    MemUtils::ReplaceBytes(client_dll.dwAutojump, 6, (PBYTE) "\x90\x90\x90\x90\x90\x90");
                    client_dll.pEngfuncs->Con_Printf("Autojump is now enabled.\n");
                }
            }
        }
    }

    namespace Server
    {
        void HookBhopCap()
        {
            server_dll.bBhopCapType = 0;
            server_dll.dwBhopCap = NULL;

            byte bhopcap_type = 0;

            DWORD dwPreventMegaBunnyJumpAddr = MemUtils::FindPattern(server_dll.dwStart, server_dll.dwLength, (PBYTE) "\x55\x8B\xEC\x83\xEC\x0C\xA1\x00\x00\x00\x00\xD9\x05\x00\x00\x00\x00\xD8\x88", "xxxxxxx????xx????xx");
            if ( !dwPreventMegaBunnyJumpAddr )
            {
                dwPreventMegaBunnyJumpAddr = MemUtils::FindPattern(server_dll.dwStart, server_dll.dwLength, (PBYTE) "\x51\x8B\x0D\x00\x00\x00\x00\xD9\x81\x00\x00\x00\x00\xD8\x0D", "xxx????xx????xx");
                if ( !dwPreventMegaBunnyJumpAddr )
                {
                    ConUtils::Log("[server dll] Could not find the PreventMegaBunnyJump() function!\n", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    return;
                }
                else
                {
                    bhopcap_type = 1;
                }
            }

            WCHAR temp[256];
            wsprintf(temp, L"[server dll] PreventMegaBunnyJump() is located at: %x\n", dwPreventMegaBunnyJumpAddr);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            if (bhopcap_type == 0)
            {
                dwPreventMegaBunnyJumpAddr += 37;
                if ( (*(BYTE*)dwPreventMegaBunnyJumpAddr == 0x74) && (*(BYTE*) (dwPreventMegaBunnyJumpAddr + 1) == 0x02) )
                {
                    server_dll.dwBhopCap = dwPreventMegaBunnyJumpAddr;
                    server_dll.bBhopCapType = bhopcap_type;
                    MemUtils::ReplaceBytes(server_dll.dwBhopCap, 2, (PBYTE) "\x90\x90");

                    if (server_dll.pEngfuncs)
                    {
                        server_dll.pEngfuncs->pfnAddServerCommand("y_sv_bhopcap", ConCmd_BhopCap);
                    }

                    ConUtils::Log("[server dll] The bhop cap was successfully stripped!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                }
                else
                {
                    ConUtils::Log("[server dll] Wrong bytes at PreventMegaBunnyJump()! Bhop cap remover disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                }
            }
            else if (bhopcap_type == 1)
            {
                dwPreventMegaBunnyJumpAddr += 34;
                if ( *(BYTE*)dwPreventMegaBunnyJumpAddr == 0x7B )
                {
                    server_dll.dwBhopCap = dwPreventMegaBunnyJumpAddr;
                    server_dll.bBhopCapType = bhopcap_type;
                    MemUtils::ReplaceBytes(server_dll.dwBhopCap, 1, (PBYTE) "\xEB");

                    if (server_dll.pEngfuncs)
                    {
                        server_dll.pEngfuncs->pfnAddServerCommand("y_sv_bhopcap", ConCmd_BhopCap);
                    }

                    ConUtils::Log("[server dll] The bhop cap was successfully stripped!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                }
                else
                {
                    ConUtils::Log("[server dll] Wrong bytes at PreventMegaBunnyJump()! Bhop cap remover disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
                }
            }
        }

        void HookAutojump()
        {
            server_dll.dwAutojump = NULL;
            memset(server_dll.pbAutojumpOrigBytes, 0, sizeof(server_dll.pbAutojumpOrigBytes));

            DWORD dwAutojumpAddr = MemUtils::FindPattern(server_dll.dwStart, server_dll.dwLength, (PBYTE) "\x8B\x81\x00\x00\x00\x00\xBB\x02\x00\x00\x00\x3B\xC3", "xx????xxxxxxx");
            if ( !dwAutojumpAddr )
            {
                ConUtils::Log("[server dll] Could not find the autojump check offset!\n", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                return;
            }

            WCHAR temp[256];
            wsprintf(temp, L"[server dll] The autojump check is located at: %x\n", dwAutojumpAddr);
            ConUtils::Log(temp, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

            dwAutojumpAddr += 326;
            if ( (*(BYTE *) dwAutojumpAddr == 0x0F) && (*(BYTE *) (dwAutojumpAddr + 1) == 0x85) )
            {
                server_dll.dwAutojump = dwAutojumpAddr;
                memcpy(server_dll.pbAutojumpOrigBytes, (void *) dwAutojumpAddr, sizeof(server_dll.pbAutojumpOrigBytes));
                MemUtils::ReplaceBytes(server_dll.dwAutojump, 6, (PBYTE) "\x90\x90\x90\x90\x90\x90");

                if (server_dll.pEngfuncs)
                {
                    server_dll.pEngfuncs->pfnAddServerCommand("y_sv_autojump", ConCmd_Autojump);
                }

                ConUtils::Log("[server dll] Autojump was enabled!\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            }
            else
            {
                ConUtils::Log("[server dll] Wrong bytes at the autojump offset! Disabling autojump...\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            }
        }

        void ConCmd_BhopCap()
        {
            if ( server_dll.pEngfuncs->pfnCmd_Argc() == 1 )
            {
                switch (server_dll.bBhopCapType)
                {
                case 0:
                    if ( *(BYTE *) server_dll.dwBhopCap == 0x74 )
                    {
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is currently enabled.\n");
                    }
                    else
                    {
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is currently disabled.\n");
                    }

                    break;

                case 1:
                    if ( *(BYTE *) server_dll.dwBhopCap == 0x7B )
                    {
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is currently enabled.\n");
                    }
                    else
                    {
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is currently disabled.\n");
                    }

                    break;
                }
            }
            else if ( server_dll.pEngfuncs->pfnCmd_Argc() > 1 )
            {
                int arg;
                sscanf(server_dll.pEngfuncs->pfnCmd_Argv(1), "%d", &arg);

                switch (server_dll.bBhopCapType)
                {
                case 0:
                    if (arg == 0)
                    {
                        MemUtils::ReplaceBytes(server_dll.dwBhopCap, 2, (PBYTE) "\x90\x90");
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is now disabled.\n");
                    }
                    else
                    {
                        MemUtils::ReplaceBytes(server_dll.dwBhopCap, 2, (PBYTE) "\x74\x02");
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is now enabled.\n");
                    }

                    break;

                case 1:
                    if (arg == 0)
                    {
                        MemUtils::ReplaceBytes(server_dll.dwBhopCap, 1, (PBYTE) "\xEB");
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is now disabled.\n");
                    }
                    else
                    {
                        MemUtils::ReplaceBytes(server_dll.dwBhopCap, 1, (PBYTE) "\x7B");
                        server_dll.pEngfuncs->pfnServerPrint("The bhop cap is now enabled.\n");
                    }

                    break;
                }
            }
        }

        void ConCmd_Autojump()
        {
            if ( server_dll.pEngfuncs->pfnCmd_Argc() == 1 )
            {
                if ( *(BYTE *) server_dll.dwAutojump == 0x0F )
                {
                    server_dll.pEngfuncs->pfnServerPrint("Autojump is currently disabled.\n");
                }
                else
                {
                    server_dll.pEngfuncs->pfnServerPrint("Autojump is currently enabled.\n");
                }
            }
            else if ( server_dll.pEngfuncs->pfnCmd_Argc() > 1 )
            {
                int arg;
                sscanf(server_dll.pEngfuncs->pfnCmd_Argv(1), "%d", &arg);

                if (arg == 0)
                {
                    MemUtils::ReplaceBytes(server_dll.dwAutojump, sizeof(server_dll.pbAutojumpOrigBytes), server_dll.pbAutojumpOrigBytes);
                    server_dll.pEngfuncs->pfnServerPrint("Autojump is now disabled.\n");
                }
                else
                {
                    MemUtils::ReplaceBytes(server_dll.dwAutojump, 6, (PBYTE) "\x90\x90\x90\x90\x90\x90");
                    server_dll.pEngfuncs->pfnServerPrint("Autojump is now enabled.\n");
                }
            }
        }
    }

    void Init()
    {
        HMODULE hClient = GetModuleHandle(L"client.dll");
        if ( !hClient )
        {
            ConUtils::Log("The client dll has not been loaded yet.\n");
        }
        else
        {
            client_dll.hDll = hClient;
            Hooks::HookClientDLL();
        }

        HMODULE hServer = GetModuleHandle(L"hl.dll");
        if ( !hServer && !(hServer = GetModuleHandle(L"opfor.dll")) && !(hServer = GetModuleHandle(L"cz.dll")) )
        {
            ConUtils::Log("The server dll has not been loaded yet.\n");
        }
        else
        {
            server_dll.hDll = hServer;
            Hooks::HookServerDLL();
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID &) Internal::OriginalLoadLibraryA, Internal::NewLoadLibraryA);
        DetourAttach(&(PVOID &) Internal::OriginalLoadLibraryW, Internal::NewLoadLibraryW);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR)
        {
            ConUtils::Log("Detoured LoadLibrary.\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else
        {
            char temp[1024];
            sprintf(temp, "Error detouring LoadLibrary: %d.\n", error);
            ConUtils::Log(temp, FOREGROUND_RED | FOREGROUND_INTENSITY);
        }
    }

    void Free()
    {
        Hooks::UnhookServerDLL();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID &) Internal::OriginalLoadLibraryA, Internal::NewLoadLibraryA);
        DetourDetach(&(PVOID &) Internal::OriginalLoadLibraryW, Internal::NewLoadLibraryW);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR)
        {
            ConUtils::Log("Removed the LoadLibrary detour.\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else
        {
            char temp[1024];
            sprintf(temp, "Error removing the LoadLibrary detour: %d.\n", error);
            ConUtils::Log(temp, FOREGROUND_RED | FOREGROUND_INTENSITY);
        }
    }

    void HookClientDLL()
    {
        if ( !client_dll.hDll )
        {
            ConUtils::Log("Attempted to hook the client dll, but it hasn't been loaded yet!\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if ( !MemUtils::GetModuleInfo(client_dll.hDll, client_dll.dwStart, client_dll.dwLength) )
        {
            ConUtils::Log("Could not obtain the client dll module info!\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        Hooks::Client::HookEngfuncs();
        Hooks::Client::HookBhopCap();
        //Hooks::Client::HookAutojump();
    }

    void HookServerDLL()
    {
        if ( !client_dll.hDll )
        {
            ConUtils::Log("Attempted to hook the server dll, but it hasn't been loaded yet!\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if ( !MemUtils::GetModuleInfo(server_dll.hDll, server_dll.dwStart, server_dll.dwLength) )
        {
            ConUtils::Log("Could not obtain the server dll module info!\n", FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        Hooks::Internal::SERVER_OriginalGiveFnptrsToDll = (void (__stdcall *) (enginefuncs_t* pengfuncsFromEngine, globalvars_t *pGlobals)) GetProcAddress(server_dll.hDll, "GiveFnptrsToDll");
        if ( !Hooks::Internal::SERVER_OriginalGiveFnptrsToDll )
        {
            ConUtils::Log("Could not obtain the GiveFnptrsToDll address! Engfuncs hooks disabled.\n", FOREGROUND_RED | FOREGROUND_INTENSITY);

            server_dll.pEngfuncs = NULL;
            Hooks::Server::HookBhopCap();
            //Hooks::Server::HookAutojump();

            return;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID &) Hooks::Internal::SERVER_OriginalGiveFnptrsToDll, Hooks::Internal::SERVER_NewGiveFnptrsToDll);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR)
        {
            ConUtils::Log("[server dll] Detoured GiveFnptrsToDll.\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else
        {
            char temp[1024];
            sprintf(temp, "[server dll] Error detouring GiveFnptrsToDll: %d. Engfuncs hooks disabled.\n", error);
            ConUtils::Log(temp, FOREGROUND_RED | FOREGROUND_INTENSITY);

            server_dll.pEngfuncs = NULL;
            Hooks::Server::HookBhopCap();
            //Hooks::Server::HookAutojump();
        }
    }

    void UnhookServerDLL()
    {
        if ( !server_dll.hDll || !server_dll.pEngfuncs )
        {
            return;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID &) Hooks::Internal::SERVER_OriginalGiveFnptrsToDll, Hooks::Internal::SERVER_NewGiveFnptrsToDll);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR)
        {
            ConUtils::Log("[server dll] Removed the GiveFnptrsToDll detour.\n", FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }
        else
        {
            char temp[1024];
            sprintf(temp, "[server dll] Error removing the GiveFnptrsToDll detour: %d.\n", error);
            ConUtils::Log(temp, FOREGROUND_RED | FOREGROUND_INTENSITY);

            server_dll.pEngfuncs = NULL;
            Hooks::Server::HookBhopCap();
            //Hooks::Server::HookAutojump();
        }
    }
}