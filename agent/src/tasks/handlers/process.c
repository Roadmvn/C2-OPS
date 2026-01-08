/*
 * process.c - Gestion des processus
 */

#include "process.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"
#include <tlhelp32.h>

int handler_process_list(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

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
  const char *header = "PID       PPID      NAME\n";
  size_t header_len = strlen(header);
  buffer = (char *)malloc(4096);
  if (!buffer) {
    CloseHandle(snapshot);
    return STATUS_NO_MEMORY;
  }
  buffer_size = 4096;
  memcpy(buffer, header, header_len);
  buffer_used = header_len;

  if (Process32First(snapshot, &entry)) {
    do {
      char line[512];
      snprintf(line, sizeof(line), "%-9lu %-9lu %s\n", entry.th32ProcessID,
               entry.th32ParentProcessID, entry.szExeFile);

      size_t line_len = strlen(line);

      /* Réalloue si nécessaire */
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

int handler_process_kill(DWORD pid) {
  if (pid == 0) {
    return STATUS_FAILURE;
  }

  HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!process) {
    return STATUS_FAILURE;
  }

  BOOL success = TerminateProcess(process, 0);
  CloseHandle(process);

  return success ? STATUS_SUCCESS : STATUS_FAILURE;
}

int handler_process_info(DWORD pid, char **output, size_t *len) {
  if (!output || !len || pid == 0) {
    return STATUS_FAILURE;
  }

  HANDLE process =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!process) {
    *output = str_dup("Failed to open process");
    *len = *output ? strlen(*output) : 0;
    return STATUS_FAILURE;
  }

  /* Récupère le chemin de l'exécutable */
  char exe_path[MAX_PATH_LEN] = {0};
  DWORD path_len = MAX_PATH_LEN;
  QueryFullProcessImageNameA(process, 0, exe_path, &path_len);

  /* Construit les infos */
  char *buffer = (char *)malloc(1024);
  if (!buffer) {
    CloseHandle(process);
    return STATUS_NO_MEMORY;
  }

  snprintf(buffer, 1024,
           "PID: %lu\n"
           "Path: %s\n",
           pid, exe_path);

  CloseHandle(process);

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}
