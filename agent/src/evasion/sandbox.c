/*
 * sandbox.c - Implémentation de la détection sandbox/VM
 */

#include "sandbox.h"

/* Seuils pour les checks */
#define MIN_CPU_COUNT 2       /* Moins de 2 CPUs = suspect */
#define MIN_RAM_GB 2          /* Moins de 2 GB = suspect */
#define MIN_UPTIME_MINUTES 30 /* Moins de 30 min = suspect */
#define MIN_DISK_SIZE_GB 60   /* Moins de 60 GB = suspect */
#define MIN_PROCESS_COUNT 50  /* Moins de 50 process = suspect */

/* Préfixes MAC des hyperviseurs courants */
static const char *VM_MAC_PREFIXES[] = {"00:0C:29", /* VMware */
                                        "00:50:56", /* VMware */
                                        "00:05:69", /* VMware */
                                        "00:1C:14", /* VMware */
                                        "08:00:27", /* VirtualBox */
                                        "00:15:5D", /* Hyper-V */
                                        "00:16:3E", /* Xen */
                                        "52:54:00", /* QEMU */
                                        "00:1A:4A", /* QEMU */
                                        NULL};

/* Clés registry des VMs */
static const char *VM_REGISTRY_KEYS[] = {
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
    "SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
    "SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    "SYSTEM\\CurrentControlSet\\Services\\vmci",
    NULL};

/* Fichiers des VMs */
static const char *VM_FILES[] = {
    "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    "C:\\Windows\\System32\\drivers\\vm3dmp.sys",
    "C:\\Windows\\System32\\vboxdisp.dll",
    "C:\\Windows\\System32\\vboxhook.dll",
    "C:\\Windows\\System32\\vmGuestLib.dll",
    "C:\\Windows\\System32\\vmhgfs.dll",
    NULL};

/* Noms de machine suspects (sandboxes connues) */
static const char *SUSPICIOUS_COMPUTER_NAMES[] = {
    "SANDBOX",  "MALWARE", "VIRUS",  "SAMPLE",
    "ANALYSIS", "CUCKOO",  "HYBRID", "TEQUILA", /* Hybrid Analysis */
    "DESKTOP-", /* Suivi de peu de caractères = VM auto-générée */
    NULL};

/* ============================================================================
 * Implémentation
 * ============================================================================
 */

bool check_cpu_count(void) {
  SYSTEM_INFO si;
  GetSystemInfo(&si);

  return si.dwNumberOfProcessors < MIN_CPU_COUNT;
}

bool check_ram_size(void) {
  MEMORYSTATUSEX mem;
  mem.dwLength = sizeof(mem);

  if (!GlobalMemoryStatusEx(&mem)) {
    return false;
  }

  /* Convertit en GB */
  DWORDLONG ram_gb = mem.ullTotalPhys / (1024 * 1024 * 1024);

  return ram_gb < MIN_RAM_GB;
}

bool check_uptime(void) {
  /* GetTickCount64 retourne le temps depuis le boot en ms */
  ULONGLONG uptime_ms = GetTickCount64();
  ULONGLONG uptime_min = uptime_ms / (1000 * 60);

  return uptime_min < MIN_UPTIME_MINUTES;
}

bool check_vm_mac_address(void) {
  /*
   * On utilise GetAdaptersInfo pour récupérer les MACs.
   * Pour l'instant, version simplifiée via le registry.
   */
  HKEY hkey;
  char adapter_name[256];
  DWORD index = 0;
  DWORD name_len;

  /* Ouvre la clé des adapters réseau */
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-"
                    "11CE-BFC1-08002BE10318}",
                    0, KEY_READ, &hkey) != ERROR_SUCCESS) {
    return false;
  }

  bool found = false;

  while (!found) {
    name_len = sizeof(adapter_name);
    if (RegEnumKeyExA(hkey, index++, adapter_name, &name_len, NULL, NULL, NULL,
                      NULL) != ERROR_SUCCESS) {
      break;
    }

    /* Ouvre la sous-clé */
    HKEY hsubkey;
    if (RegOpenKeyExA(hkey, adapter_name, 0, KEY_READ, &hsubkey) ==
        ERROR_SUCCESS) {
      char mac[32] = {0};
      DWORD mac_len = sizeof(mac);
      DWORD type;

      if (RegQueryValueExA(hsubkey, "NetworkAddress", NULL, &type, (LPBYTE)mac,
                           &mac_len) == ERROR_SUCCESS &&
          type == REG_SZ) {

        /* Compare avec les préfixes VM */
        for (int i = 0; VM_MAC_PREFIXES[i] != NULL; i++) {
          /* Extrait le préfixe sans les ':' pour comparaison */
          char prefix_clean[8] = {0};
          const char *p = VM_MAC_PREFIXES[i];
          int j = 0;
          while (*p && j < 6) {
            if (*p != ':') {
              prefix_clean[j++] = *p;
            }
            p++;
          }
          /* Compare les 6 premiers caractères (3 octets MAC) */
          if (strncmp(mac, prefix_clean, 6) == 0) {
            found = true;
            break;
          }
        }
      }

      RegCloseKey(hsubkey);
    }
  }

  RegCloseKey(hkey);
  return found;
}

bool check_vm_registry_keys(void) {
  for (int i = 0; VM_REGISTRY_KEYS[i] != NULL; i++) {
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, VM_REGISTRY_KEYS[i], 0, KEY_READ,
                      &hkey) == ERROR_SUCCESS) {
      RegCloseKey(hkey);
      return true;
    }
  }

  return false;
}

bool check_vm_files(void) {
  for (int i = 0; VM_FILES[i] != NULL; i++) {
    DWORD attrs = GetFileAttributesA(VM_FILES[i]);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
      return true;
    }
  }

  return false;
}

bool check_computer_name(void) {
  char name[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD size = sizeof(name);

  if (!GetComputerNameA(name, &size)) {
    return false;
  }

  /* Convertit en uppercase pour la comparaison */
  for (DWORD i = 0; i < size; i++) {
    if (name[i] >= 'a' && name[i] <= 'z') {
      name[i] -= 32;
    }
  }

  /* Check les noms suspects */
  for (int i = 0; SUSPICIOUS_COMPUTER_NAMES[i] != NULL; i++) {
    if (strstr(name, SUSPICIOUS_COMPUTER_NAMES[i]) != NULL) {
      return true;
    }
  }

  /* Nom trop court (genre "WIN-XXXXXXXX" avec peu de X) */
  if (size < 8) {
    return true;
  }

  return false;
}

bool check_disk_size(void) {
  ULARGE_INTEGER free_bytes, total_bytes, total_free;

  if (!GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free)) {
    return false;
  }

  /* Convertit en GB */
  ULONGLONG disk_gb = total_bytes.QuadPart / (1024ULL * 1024ULL * 1024ULL);

  return disk_gb < MIN_DISK_SIZE_GB;
}

bool check_process_count(void) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  int count = 0;

  if (Process32First(snapshot, &entry)) {
    do {
      count++;
    } while (Process32Next(snapshot, &entry));
  }

  CloseHandle(snapshot);

  return count < MIN_PROCESS_COUNT;
}

bool check_user_interaction(void) {
  /*
   * Check si la souris a bougé récemment.
   * Les sandboxes automatiques n'ont souvent pas d'interaction.
   */
  POINT pt1, pt2;

  GetCursorPos(&pt1);
  Sleep(500); /* Attend 500ms */
  GetCursorPos(&pt2);

  /* Si la souris n'a pas bougé et est à (0,0), c'est suspect */
  if (pt1.x == pt2.x && pt1.y == pt2.y && pt1.x == 0 && pt1.y == 0) {
    return true;
  }

  /* Check le temps depuis la dernière input */
  LASTINPUTINFO lii;
  lii.cbSize = sizeof(lii);

  if (GetLastInputInfo(&lii)) {
    ULONGLONG idle_time = GetTickCount64() - (ULONGLONG)lii.dwTime;
    /* Si aucune input depuis plus de 10 minutes, suspect */
    if (idle_time > 10 * 60 * 1000) {
      return true;
    }
  }

  return false;
}

bool is_sandbox_environment(void) {
  int suspicion_score = 0;

  /* Chaque check ajoute au score de suspicion */
  if (check_cpu_count())
    suspicion_score += 1;
  if (check_ram_size())
    suspicion_score += 1;
  if (check_uptime())
    suspicion_score += 2;
  if (check_disk_size())
    suspicion_score += 1;
  if (check_process_count())
    suspicion_score += 1;

  /* Les checks VM sont plus fiables */
  if (check_vm_registry_keys())
    suspicion_score += 3;
  if (check_vm_files())
    suspicion_score += 3;
  if (check_vm_mac_address())
    suspicion_score += 2;

  /* Checks comportementaux */
  if (check_computer_name())
    suspicion_score += 2;

  /*
   * On ne fait pas le check d'interaction utilisateur ici
   * car ça prend du temps (500ms) et peut bloquer.
   * À faire en background ou à la demande.
   */

  /* Score >= 4 = environnement suspect */
  return suspicion_score >= 4;
}
