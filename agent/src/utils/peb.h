/*
 * peb.h - PEB Walking pour résolution dynamique d'APIs
 *
 * Au lieu d'utiliser GetProcAddress (qui peut être hookée par les EDRs),
 * on parcourt le PEB pour trouver les DLLs chargées et résoudre
 * les fonctions manuellement.
 */

#ifndef PEB_H
#define PEB_H

#include "../../include/common.h"
#include "../../include/ntdefs.h"

/*
 * Récupère l'adresse de base d'un module par son hash.
 * Utilise un hash au lieu du nom pour pas avoir de strings en clair.
 *
 * Params:
 *   module_hash - Hash DJB2 du nom du module (en lowercase)
 *
 * Retourne l'adresse de base du module ou NULL.
 */
HMODULE peb_get_module(uint32_t module_hash);

/*
 * Récupère l'adresse d'une fonction exportée par hash.
 *
 * Params:
 *   module      - Handle du module
 *   func_hash   - Hash DJB2 du nom de la fonction
 *
 * Retourne l'adresse de la fonction ou NULL.
 */
FARPROC peb_get_proc(HMODULE module, uint32_t func_hash);

/*
 * Combine les deux : récupère une fonction d'un module par hash.
 *
 * Params:
 *   module_hash - Hash du nom du module
 *   func_hash   - Hash du nom de la fonction
 *
 * Retourne l'adresse de la fonction ou NULL.
 */
FARPROC peb_get_function(uint32_t module_hash, uint32_t func_hash);

/* ============================================================================
 * Hashes pré-calculés des modules courants
 * Calculés avec l'algo DJB2 sur le nom en lowercase
 * ============================================================================
 */
#define HASH_KERNEL32_DLL 0x6A4ABC5B   /* kernel32.dll */
#define HASH_NTDLL_DLL 0x3CFA685D      /* ntdll.dll */
#define HASH_KERNELBASE_DLL 0x03EB43A8 /* kernelbase.dll */
#define HASH_USER32_DLL 0x63C84283     /* user32.dll */
#define HASH_ADVAPI32_DLL 0x76C23A5C   /* advapi32.dll */
#define HASH_WINHTTP_DLL 0x35B24524    /* winhttp.dll */
#define HASH_WS2_32_DLL 0x75E5D2C2     /* ws2_32.dll */

/* ============================================================================
 * Hashes pré-calculés des fonctions courantes
 * ============================================================================
 */
/* kernel32.dll */
#define HASH_LOADLIBRARYA 0xEC0E4E8E   /* LoadLibraryA */
#define HASH_GETPROCADDRESS 0x7C0DFCAA /* GetProcAddress */
#define HASH_VIRTUALALLOC 0x91AFCA54   /* VirtualAlloc */
#define HASH_VIRTUALFREE 0x30633AC3    /* VirtualFree */
#define HASH_VIRTUALPROTECT 0x7946C61B /* VirtualProtect */
#define HASH_CREATEPROCESSA 0x16B3FE72 /* CreateProcessA */
#define HASH_CREATEPIPE 0xE27D6F28     /* CreatePipe */
#define HASH_READFILE 0xBB5F9EAD       /* ReadFile */
#define HASH_WRITEFILE 0xE80A791F      /* WriteFile */
#define HASH_CLOSEHANDLE 0x0FFD97FB    /* CloseHandle */
#define HASH_SLEEP 0xDB2D49B0          /* Sleep */
#define HASH_GETLASTERROR 0x75DA1966   /* GetLastError */

/* ntdll.dll */
#define HASH_NTALLOCATEVIRTUALMEMORY 0xF783B8EC /* NtAllocateVirtualMemory */
#define HASH_NTFREEVIRTUALMEMORY 0x2802C609     /* NtFreeVirtualMemory */
#define HASH_NTPROTECTVIRTUALMEMORY 0x50E92888  /* NtProtectVirtualMemory */
#define HASH_NTQUERYINFORMATIONPROCESS                                         \
  0xF5A65ABD                             /* NtQueryInformationProcess */
#define HASH_NTDELAYEXECUTION 0x2E6F0146 /* NtDelayExecution */
#define HASH_NTCLOSE 0x40D6E69D          /* NtClose */
#define HASH_RTLGETVERSION 0xADEDCAB9    /* RtlGetVersion */

#endif /* PEB_H */
