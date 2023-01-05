#include "pch.h"
#include "utils.h"

BOOL isPartOf(const char* w1, const char* w2)
{
    int i = 0;
    int j = 0;


    while (w1[i] != '\0') {
        if (w1[i] == w2[j])
        {
            int init = i;
            while (w1[i] == w2[j] && w2[j] != '\0')
            {
                j++;
                i++;
            }
            if (w2[j] == '\0') {
                return true;
            }
            j = 0;
        }
        i++;
    }
    return false;
}


BOOL ListProcessThreads(DWORD dwOwnerPID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        printError(L"Thread32First");  // Show cause of failure
        return(FALSE);
    }
    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32))
    {
        printError(L"Thread32First");  // Show cause of failure
        CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
        return(FALSE);
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            _tprintf(TEXT("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
            _tprintf(TEXT("\n     base priority  = %d"), te32.tpBasePri);
            _tprintf(TEXT("\n     delta priority = %d"), te32.tpDeltaPri);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    _tprintf(TEXT("\n"));

    //  Don't forget to clean up the snapshot object.
    CloseHandle(hThreadSnap);
    return(TRUE);
}

void printError(LPCWSTR msg)
{
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        sysMsg, 256, NULL);

    // Trim the end of the line and terminate it with a null
    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    // Display the message
    std::wcout << std::endl << msg;
    _tprintf(TEXT(" - WARNING: failed with error %d (%s)"), eNum, sysMsg);
}