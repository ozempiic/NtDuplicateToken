#include <windows.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <chrono>
#include <sddl.h>
#include <C:\Users\betty\Desktop\idk\Detours-4.0.1\include\detours.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *pNtDuplicateToken)(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    PHANDLE NewTokenHandle
);

pNtDuplicateToken OriginalNtDuplicateToken = nullptr;
bool hookInstalled = false;
bool loggingDone = false;

void LogTokenInformation(HANDLE TokenHandle) {
    if (loggingDone) return;

    std::ofstream logFile("C:\\Users\\betty\\Desktop\\idk\\lol.txt", std::ios_base::app);
    if (!logFile.is_open()) return;

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    logFile << std::ctime(&now);

    DWORD tokenInfoLength = 0;
    if (!GetTokenInformation(TokenHandle, TokenUser, nullptr, 0, &tokenInfoLength) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::unique_ptr<BYTE[]> tokenUserBuffer(new BYTE[tokenInfoLength]);
        if (tokenUserBuffer && GetTokenInformation(TokenHandle, TokenUser, tokenUserBuffer.get(), tokenInfoLength, &tokenInfoLength)) {
            TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenUserBuffer.get());
            char username[256], domain[256];
            DWORD usernameLen = sizeof(username);
            DWORD domainLen = sizeof(domain);
            SID_NAME_USE sidType;

            if (LookupAccountSid(nullptr, tokenUser->User.Sid, username, &usernameLen, domain, &domainLen, &sidType)) {
                logFile << "User: " << domain << "\\" << username << "\n";
            } else {
                logFile << "failed to lookup account SID\n";
            }
        } else {
            logFile << "failed to get token information\n";
        }
    } else {
        logFile << "failed to determine token info length\n";
    }

    logFile.close();
    loggingDone = true;
}

NTSTATUS NTAPI HookedNtDuplicateToken(
    HANDLE ExistingTokenHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType,
    PHANDLE NewTokenHandle
) {
    LogTokenInformation(ExistingTokenHandle);

    return OriginalNtDuplicateToken(
        ExistingTokenHandle,
        DesiredAccess,
        ObjectAttributes,
        EffectiveOnly,
        TokenType,
        NewTokenHandle
    );
}

void HookNtDuplicateToken() {
    if (!hookInstalled) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            OriginalNtDuplicateToken = reinterpret_cast<pNtDuplicateToken>(GetProcAddress(hNtdll, "NtDuplicateToken"));
            if (OriginalNtDuplicateToken) {
                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(&(PVOID&)OriginalNtDuplicateToken, HookedNtDuplicateToken);
                if (DetourTransactionCommit() == NO_ERROR) {
                    hookInstalled = true;
                    MessageBox(nullptr, "NtDuplicateToken has been hooked", ";3", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBox(nullptr, "failed to hook NtDuplicateToken", "FAILED!!! LOSER", MB_OK | MB_ICONERROR);
                }
            }
        }
    }
}

extern "C" __declspec(dllexport) void TestLogging() {
    HANDLE currentToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentToken)) {
        LogTokenInformation(currentToken);
        CloseHandle(currentToken);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            HookNtDuplicateToken();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
