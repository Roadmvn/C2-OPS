/*
 * shell.c - Exécution de commandes via cmd.exe
 *
 * Utilise des pipes pour capturer stdout/stderr.
 */

#include "shell.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"

int handler_shell_exec(const char *command, char **output, size_t *len) {
  if (!command || !output || !len) {
    return STATUS_FAILURE;
  }

  *output = NULL;
  *len = 0;

  /* Crée les pipes pour la redirection */
  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  HANDLE stdout_read = NULL;
  HANDLE stdout_write = NULL;

  if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
    return STATUS_FAILURE;
  }

  /* Le handle de lecture ne doit pas être hérité */
  SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

  /* Configure le process */
  STARTUPINFOA si;
  PROCESS_INFORMATION pi;

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdError = stdout_write;
  si.hStdOutput = stdout_write;
  si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE; /* Pas de fenêtre visible */

  ZeroMemory(&pi, sizeof(pi));

  /* Construit la commande complète */
  char cmd_line[4096];
  snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", command);

  /* Lance le process */
  BOOL success =
      CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE, /* Inherit handles */
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

  if (!success) {
    CloseHandle(stdout_read);
    CloseHandle(stdout_write);
    return STATUS_FAILURE;
  }

  /* Ferme le handle d'écriture pour pouvoir détecter la fin */
  CloseHandle(stdout_write);

  /* Lit la sortie */
  char *buffer = NULL;
  size_t total_size = 0;
  char read_buffer[4096];
  DWORD bytes_read;

  while (ReadFile(stdout_read, read_buffer, sizeof(read_buffer), &bytes_read,
                  NULL) &&
         bytes_read > 0) {
    /* Réalloue le buffer */
    char *new_buffer = (char *)realloc(buffer, total_size + bytes_read + 1);
    if (!new_buffer) {
      free(buffer);
      CloseHandle(stdout_read);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      return STATUS_NO_MEMORY;
    }
    buffer = new_buffer;

    memcpy(buffer + total_size, read_buffer, bytes_read);
    total_size += bytes_read;
  }

  if (buffer) {
    buffer[total_size] = '\0';
  }

  /* Attend la fin du process (max 30 secondes) */
  WaitForSingleObject(pi.hProcess, 30000);

  /* Cleanup */
  CloseHandle(stdout_read);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  *output = buffer;
  *len = total_size;

  return STATUS_SUCCESS;
}
