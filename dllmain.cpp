/*
* 
* HookTools
* Basic injectable for analyzing the behavior of evasive usermode malware
* 
*/

#include "pch.h"

// Settings
#define moduleNamePassthrough 0 // Allow process to grab module names
#define openProcessPassthrough 0 // Allow process to open handles to other processes
#define processCanOpenHandleToSelf 0 // Allow the process to use OpenProcess to get a handle to itself
#define globalSnapshotPassthrough 0 // Allow process to snapshot any process
#define selfSnapshotPassthrough 0 // Allow process to snapshot itself
#define allowHooks 0 // Allow process to make global hooks

// DLL Blacklist
LPCSTR dllBlacklist[] = {
    "awt123.dll",
    "awt321.dll"
};

// Process blacklist
LPCWSTR processBlacklist[] = {
    L"example.exe",
};

#include <iostream>
#include <chrono>
#include <thread>
#include <winternl.h>
#include <Psapi.h>
#include <processthreadsapi.h>
#include <libloaderapi.h>
#include "utils.h"

#if defined(_M_X64)
// TODO
// add preprocessing directive for 
// 64bit detours library later
#endif


// Definitions - bare jmp hooks
static HANDLE(WINAPI* originalCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID) = CreateToolhelp32Snapshot;
static HWND(WINAPI* originalGetFocus)() = GetFocus;

// Definitions - offset jmp hooks
typedef HMODULE(WINAPI* loadLibraryA)(LPCSTR lpLibFileName);
typedef HHOOK(WINAPI* setWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId);
typedef LRESULT(WINAPI* callNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
typedef HANDLE(WINAPI* openProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef DWORD(WINAPI* getModuleFileNameA)(HMODULE hModule, LPSTR lpFileName, DWORD _Size);
typedef VOID(WINAPI* raiseException)(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments);
typedef INT(cdecl* memCmp)(void const* _Buf1, void const* _Buf2, size_t _Size);
loadLibraryA originalLoadLibraryA = reinterpret_cast<loadLibraryA>(GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "LoadLibraryA"));
setWindowsHookExW originalSetWindowsHookExW = reinterpret_cast<setWindowsHookExW>(GetProcAddress(GetModuleHandle(L"user32.dll"), "SetWindowsHookExAW"));
callNextHookEx originalCallNextHookEx = reinterpret_cast<callNextHookEx>(GetProcAddress(GetModuleHandle(L"win32u.dll"), "NtUserCallNextHookEx"));
openProcess originalOpenProcess = reinterpret_cast<openProcess>(GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "OpenProcess"));
getModuleFileNameA originalGetModuleFileNameA = reinterpret_cast<getModuleFileNameA>(GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "GetModuleFileNameA"));
raiseException originalRaiseException = reinterpret_cast<raiseException>(GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "RaiseException"));
memCmp originalmemCmp = reinterpret_cast<memCmp>(GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "memcmp"));

template<typename Function>
PVOID correctOffset(Function function, int offset)
{
    uintptr_t uipFunction = reinterpret_cast<uintptr_t>(function) + offset;
    PVOID pvOffsetFunction = reinterpret_cast<PVOID>(uipFunction);
    return pvOffsetFunction;
}

HWND hookedGetFocus()
{
    return originalGetFocus();
}

DWORD hookedGetModuleFileNameA(HMODULE hModule, LPSTR lpFileName, DWORD _Size)
{
    std::cout << std::endl;
    std::cout << "Grabbed a module file name " << std::endl;
    std::cout << " - " << lpFileName << std::endl;
    if (moduleNamePassthrough)
    {
        return originalGetModuleFileNameA(hModule, lpFileName, _Size);
    }
    SetLastError(ERROR_MOD_NOT_FOUND);
    return NULL;
}

INT hookedMemCmp(void const* _Buf1, void const* _Buf2, size_t _Size)
{
    return originalmemCmp(_Buf1, _Buf2, _Size);
}

VOID WINAPI hookedRaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments)
{
#ifdef _DEBUG
    std::cout << std::endl;
    std::cout << "Excpetion was raised" << std::endl;
    std::cout << " - dwExceptionCode: " << std::hex << dwExceptionCode << std::endl;
    std::cout << " - dwExceptionFlags: " << dwExceptionFlags << std::endl;
    std::cout << " - lpArguments: " << lpArguments << std::endl;
#endif
    return originalRaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
}

HMODULE WINAPI hookedLoadLibraryA(LPCSTR lpLibFileName)
{
    std::cout << std::endl;
    for (int i = 0; i <= (sizeof(dllBlacklist) / sizeof(LPCSTR)) - 1; i++)
    {
        if (isPartOf(lpLibFileName, dllBlacklist[i]) == 1)
        {
            std::cout << "Tried to load blacklisted library" << std::endl;
            std::cout << " - Lib: " << lpLibFileName << std::endl;
            SetLastError(ERROR_INVALID_LIBRARY);
            return NULL;
        }
    }
    std::cout << "Loaded a library into memory" << std::endl;
    std::cout << " - Lib: " << lpLibFileName << std::endl;
    HMODULE result = originalLoadLibraryA(lpLibFileName);
    return result;
}

HANDLE WINAPI hookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    std::cout << std::endl;
    if (dwProcessId == 0x00000000) // Hook check, pass it through
    {
        return originalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    if (dwProcessId == GetCurrentProcessId())
    {
        if (processCanOpenHandleToSelf == 1)
        {
            return originalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        }
    }

    WCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    HANDLE hProcess = originalOpenProcess(PROCESS_QUERY_INFORMATION|TOKEN_ALL_ACCESS, bInheritHandle, dwProcessId);
    if (hProcess != NULL)
    {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            if (GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR)) == 0)
            {
                printError(L"GetMduleBaseName");
            }
            for (int i = 0; i <= (sizeof(processBlacklist) / sizeof(LPWSTR)) - 1; i++)
            {
                if (wcscmp(szProcessName, processBlacklist[i]) == 0)
                {
                    std::cout << "[!] Process tried to open blacklisted process" << std::endl;
                    std::cout << " - Desired access: " << dwDesiredAccess << std::endl;
                    std::cout << " - Process ID: " << dwProcessId << std::endl;
                    std::wcout << " - Process name: " << szProcessName << std::endl;
                    SetLastError(ERROR_INVALID_ACCESS);
                    return NULL;
                }
            }
        }
        else
        {
            printError(L"EnumProcessModules");
            std::cout << " - Its probably interfacing with a kernel driver" << std::endl;
        }
        CloseHandle(hProcess);
    }
    else
    {
        printError(L"OpenProcess");
    }
    
    std::cout << "[!] Opened another process" << std::endl;
    std::cout << " - Desired access: " << dwDesiredAccess << std::endl;
    std::cout << " - Process ID: " << dwProcessId << std::endl;
    std::wcout << " - Process name: " << szProcessName << std::endl;
    if (openProcessPassthrough)
    {
        return originalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }
    SetLastError(ERROR_PROCESS_IS_PROTECTED);
    return NULL;
}

HANDLE WINAPI hookedCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    std::cout << std::endl;
    std::cout << "[!] Tried to take a snapshot of another process" << std::endl;
    std::cout << " - Process ID: " << th32ProcessID << std::endl;
    std::cout << " - Flags: " << dwFlags << std::endl;
    if (globalSnapshotPassthrough)
    {
        return originalCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
    }
    if ((th32ProcessID == GetCurrentProcessId() || th32ProcessID == 0) && selfSnapshotPassthrough == 0)
    {
        std::cout << " - Denied snapshot of self" << std::endl;
    }
    SetLastError(ERROR_INVALID_HANDLE);
    return INVALID_HANDLE_VALUE;
}

LRESULT WINAPI hookedCallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam)
{
    std::cout << std::endl;
    if (allowHooks)
    {
        return originalCallNextHookEx(hhk, nCode, wParam, lParam);
    }
    std::cout << "[!!!] Oops, we missed a hook" << std::endl;
    std::cout << " - WPARAM: " << wParam << std::endl;
    std::cout << " - LPARAM: " << lParam << std::endl;
    if (hhk != NULL)
    {
        std::cout << " - Handle was passed, trying to unhook ..." << std::endl;
        UnhookWindowsHookEx(hhk);
    }
    SetLastError(ERROR_INVALID_HOOK_HANDLE);
    return NULL;
}

HHOOK WINAPI hookedSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hMod, DWORD dwThreadId)
{
    switch (idHook) {
    case WH_CALLWNDPROC:
        std::cout << "Host process hooked WH_CALLWNDPROC" << std::endl;
        break;
    case WH_CALLWNDPROCRET:
        std::cout << "Host process hooked WH_CALLWNDPROCRET" << std::endl;
        break;
    case WH_CBT:
        std::cout << "Host process hooked WH_CBT" << std::endl;
        break;
    case WH_DEBUG:
        std::cout << "Host process hooked WH_DEBUG" << std::endl;
        break;
    case WH_FOREGROUNDIDLE:
        std::cout << "Host process hooked WH_FOREGROUNDIDLE" << std::endl;
        break;
    case WH_JOURNALPLAYBACK:
        std::cout << "Host process hooked WH_JOURNALPLAYBACK" << std::endl;
        break;
    case WH_JOURNALRECORD:
        std::cout << "Host process hooked WH_JOURNALRECORD" << std::endl;
        break;
    case WH_MOUSE_LL:
        std::cout << "Host process hooked WH_MOUSE_LL" << std::endl;
        break;
    case WH_GETMESSAGE:
        std::cout << "Host process hooked WH_GETMESSAGE" << std::endl;
        break;
    case WH_KEYBOARD:
        std::cout << "Host process hooked WH_KEYBOARD" << std::endl;
        break;
    case WH_KEYBOARD_LL:
        std::cout << "Host process hooked WH_KEYBOARD_LL" << std::endl;
        break;
    case WH_MOUSE:
        std::cout << "Host process hooked WH_MOUSE" << std::endl;
        break;
    case WH_MSGFILTER:
        std::cout << "Host process hooked WH_MSGFILTER" << std::endl;
        break;
    case WH_SHELL:
        std::cout << "Host process hooked WH_SHELL" << std::endl;
        break;
    case WH_SYSMSGFILTER:
        std::cout << "Host process hooked WH_SYSMSGFILTER" << std::endl;
        break;
    default:
        std::cout << "Host process hooked unknown idHook " << idHook << std::endl;
        break;
    }

    std::cout << " - Hook procedure: " << lpfn << std::endl;
    std::cout << " - Instance: " << hMod << std::endl;
    std::cout << " - Thread id: " << dwThreadId << std::endl;
    if (allowHooks)
    {
        return originalSetWindowsHookExW(idHook, lpfn, hMod, dwThreadId);
    }
    SetLastError(ERROR_HOOK_NOT_INSTALLED);
    return NULL;
}

BOOL installHooks()
{
    PVOID correctLoadLibraryA = correctOffset(LoadLibraryA, 2);
    PVOID correctSetWindowsHookExW = correctOffset(SetWindowsHookExW, 2);
    PVOID correctCallNextHookEx = correctOffset(CallNextHookEx, 2);
    PVOID correctOpenProcess = correctOffset(OpenProcess, 2);
    PVOID correctRaiseException = correctOffset(RaiseException, 2);
    PVOID correctGetModuleFileNameA = correctOffset(GetModuleFileNameA, 2);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // Bare hooks
    DetourAttach(&(PVOID&)originalCreateToolhelp32Snapshot, hookedCreateToolhelp32Snapshot);
    //DetourAttach(&(PVOID&)originalGetFocus, hookedGetFocus);

    // Stealth hooks
    DetourAttach(&(PVOID&)correctCallNextHookEx, hookedCallNextHookEx);
    DetourAttach(&(PVOID&)correctOpenProcess, hookedOpenProcess);
    DetourAttach(&(PVOID&)correctRaiseException, hookedRaiseException);
    DetourAttach(&(PVOID&)correctLoadLibraryA, hookedLoadLibraryA);
    DetourAttach(&(PVOID&)correctGetModuleFileNameA, hookedGetModuleFileNameA);
    DetourAttach(&(PVOID&)correctSetWindowsHookExW, hookedSetWindowsHookExW);
    return DetourTransactionCommit();
}

BOOL uninstallHooks()
{
    PVOID correctLoadLibraryA = correctOffset(LoadLibraryA, 2);
    PVOID correctCallNextHookEx = correctOffset(CallNextHookEx, 2);
    PVOID correctOpenProcess = correctOffset(OpenProcess, 2);
    PVOID correctRaiseException = correctOffset(RaiseException, 2);
    PVOID correctGetModuleFileNameA = correctOffset(GetModuleFileNameA, 2);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)correctCallNextHookEx, hookedCallNextHookEx);
    DetourDetach(&(PVOID&)correctOpenProcess, hookedOpenProcess);
    DetourDetach(&(PVOID&)correctRaiseException, hookedRaiseException);
    DetourDetach(&(PVOID&)correctLoadLibraryA, hookedLoadLibraryA);
    DetourDetach(&(PVOID&)correctGetModuleFileNameA, hookedGetModuleFileNameA);
    DetourDetach(&(PVOID&)originalCreateToolhelp32Snapshot, hookedCreateToolhelp32Snapshot);
    //DetourAttach(&(PVOID&)originalGetFocus, hookedGetFocus);
    return DetourTransactionCommit();
}


DWORD WINAPI MainThread(HMODULE hModule)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    std::cout << "Address: " << originalCreateToolhelp32Snapshot << std::endl;

    if (!installHooks())
    {
        std::cout << "Everything is setup correctly, monitoring..." << std::endl;
    }

    ListProcessThreads(GetCurrentProcessId());

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!uninstallHooks())
    {
        std::cout << "Hooks removed successfully" << std::endl;
    }
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr));
    }
    return TRUE;
}

