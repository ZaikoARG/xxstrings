#include "StdAfx.h"
#include "basics.h"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

class ErrorPrinter {
public:
    virtual void printError(DWORD errorCode, const std::wstring& functionName) = 0;
    virtual ~ErrorPrinter() {}
};

class ConsoleErrorPrinter : public ErrorPrinter {
public:
    void printError(DWORD errorCode, const std::wstring& functionName) override {
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0, nullptr);

        std::wstring errorMessage = L"";
        errorMessage += functionName;
        errorMessage += L" failed with error ";
        errorMessage += std::to_wstring(errorCode);
        errorMessage += L": ";
        errorMessage += static_cast<LPTSTR>(lpMsgBuf);

        std::wcerr << errorMessage << std::endl;

        LocalFree(lpMsgBuf);
    }
};

void PrintLastError(const std::wstring& functionName) {
    DWORD dw = GetLastError();
    std::unique_ptr<ErrorPrinter> errorPrinter = std::make_unique<ConsoleErrorPrinter>();
    errorPrinter->printError(dw, functionName);
}
