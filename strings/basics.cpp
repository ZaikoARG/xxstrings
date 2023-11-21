#include "StdAfx.h"
#include "basics.h"

void PrintLastError(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code
    LPVOID lpMsgBuf;
    LPTSTR lpDisplayBuf = NULL; // Initialize lpDisplayBuf to NULL
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Allocate memory for the display buffer and check for allocation success
    lpDisplayBuf = (LPTSTR)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));

    if (lpDisplayBuf != NULL) {
        // Format and print the error message
        StringCchPrintf(lpDisplayBuf,
            LocalSize(lpDisplayBuf) / sizeof(TCHAR),
            TEXT("%s failed with error %d: %s"),
            lpszFunction, dw, (LPCTSTR)lpMsgBuf);  // Corrected the argument type

        fwprintf(stderr, lpDisplayBuf);

        // Free allocated memory
        LocalFree(lpDisplayBuf);
    }
    else {
        // Handle the case when memory allocation fails
        fwprintf(stderr, TEXT("Failed to allocate memory for error message."));
    }

    LocalFree(lpMsgBuf);
}
