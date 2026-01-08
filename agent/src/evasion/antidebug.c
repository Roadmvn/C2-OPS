/*
 * antidebug.c - Implémentation des techniques anti-debug
 */

#include "antidebug.h"
#include "../../include/ntdefs.h"
#include "../utils/peb.h"
#include "../utils/strings.h"
#include "syscalls.h"

/* ============================================================================
 * Hashes des noms de process d'analyse
 * ============================================================================
 */
static const uint32_t ANALYSIS_PROCESS_HASHES[] = {
    0x85D48D7C, /* ollydbg.exe */
    0xB127D74B, /* x64dbg.exe */
    0x9F3D437B, /* x32dbg.exe */
    0xCB6F2C8A, /* idaq.exe */
    0xD94C6E9D, /* idaq64.exe */
    0x1B583EB4, /* ida.exe */
    0xE54F4C8D, /* ida64.exe */
    0x3E2C945D, /* windbg.exe */
    0x05C91F23, /* processhacker.exe */
    0x72F3D749, /* procmon.exe */
    0x85A74E8B, /* procmon64.exe */
    0xA92C8F4D, /* wireshark.exe */
    0xF4D8C2B1, /* fiddler.exe */
    0x12345678, /* cheatengine-x86_64.exe (placeholder) */
    0};

/* ============================================================================
 * Implémentation
 * ============================================================================
 */

bool check_peb_being_debugged(void) {
  PPEB peb = NtCurrentPeb();
  if (!peb) {
    return false;
  }

  return peb->BeingDebugged != 0;
}

bool check_debug_port(void) {
  HANDLE debug_port = NULL;
  NTSTATUS status;

  status = sys_NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort,
                                         &debug_port, sizeof(debug_port), NULL);

  if (NT_SUCCESS(status) && debug_port != NULL) {
    return true;
  }

  return false;
}

bool check_debug_flags(void) {
  DWORD debug_flags = 0;
  NTSTATUS status;

  status =
      sys_NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags,
                                    &debug_flags, sizeof(debug_flags), NULL);

  /* Si debug_flags est 0, on est debuggé */
  if (NT_SUCCESS(status) && debug_flags == 0) {
    return true;
  }

  return false;
}

bool check_debug_object_handle(void) {
  HANDLE debug_object = NULL;
  NTSTATUS status;

  status = sys_NtQueryInformationProcess(
      GetCurrentProcess(), ProcessDebugObjectHandle, &debug_object,
      sizeof(debug_object), NULL);

  /* Si on a un handle valide, on est debuggé */
  if (NT_SUCCESS(status)) {
    return true;
  }

  return false;
}

bool check_timing_attack(void) {
  /*
   * L'idée: on mesure le temps d'exécution d'une opération.
   * Si c'est trop long, y'a probablement un debugger.
   */
  LARGE_INTEGER freq, start, end;

  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  /* Opération simple qui devrait être rapide */
  volatile int x = 0;
  for (int i = 0; i < 100; i++) {
    x += i;
  }

  QueryPerformanceCounter(&end);

  /* Calcule le temps en microsecondes */
  double elapsed_us =
      (double)(end.QuadPart - start.QuadPart) * 1000000.0 / freq.QuadPart;

  /* Si ça prend plus de 1ms, c'est suspect (devrait prendre < 100us) */
  if (elapsed_us > 1000.0) {
    return true;
  }

  return false;
}

bool check_analysis_processes(void) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);

  bool found = false;

  if (Process32First(snapshot, &entry)) {
    do {
      /* Calcule le hash du nom du process */
      uint32_t hash = str_hash(entry.szExeFile);

      /* Compare avec la liste */
      for (int i = 0; ANALYSIS_PROCESS_HASHES[i] != 0; i++) {
        if (hash == ANALYSIS_PROCESS_HASHES[i]) {
          found = true;
          break;
        }
      }

      if (found)
        break;

    } while (Process32Next(snapshot, &entry));
  }

  CloseHandle(snapshot);
  return found;
}

bool check_analysis_windows(void) {
  /*
   * Check si des fenêtres d'outils d'analyse sont ouvertes.
   * On pourrait faire un EnumWindows mais c'est plus lourd.
   * Pour l'instant on fait un check simple.
   */

  /* List des noms de classes de fenêtres suspectes */
  const char *suspicious_classes[] = {"OLLYDBG", "ID", /* IDA */
                                      "WinDbgFrameClass", "ProcessHacker",
                                      NULL};

  for (int i = 0; suspicious_classes[i] != NULL; i++) {
    HWND hwnd = FindWindowA(suspicious_classes[i], NULL);
    if (hwnd != NULL) {
      return true;
    }
  }

  return false;
}

bool is_debugger_present(void) {
  /* Combine plusieurs checks pour plus de fiabilité */

  /* Check 1: PEB BeingDebugged flag (le plus basique) */
  if (check_peb_being_debugged()) {
    return true;
  }

  /* Check 2: Debug port via NtQueryInformationProcess */
  if (check_debug_port()) {
    return true;
  }

  /* Check 3: Debug flags */
  if (check_debug_flags()) {
    return true;
  }

  /* Check 4: Debug object handle */
  if (check_debug_object_handle()) {
    return true;
  }

  /*
   * On commente le timing check car il peut donner des faux positifs
   * sur des systèmes lents ou chargés.
   */
  // if (check_timing_attack()) {
  //     return true;
  // }

  /* Check 5: Process d'analyse en cours */
  if (check_analysis_processes()) {
    return true;
  }

  /* Check 6: Fenêtres d'outils d'analyse */
  if (check_analysis_windows()) {
    return true;
  }

  return false;
}
