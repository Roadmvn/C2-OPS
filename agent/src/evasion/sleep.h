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
 * Cleanup du module.
 */
void sleep_cleanup(void);

#endif /* SLEEP_H */
