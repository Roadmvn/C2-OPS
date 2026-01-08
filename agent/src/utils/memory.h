/*
 * memory.h - Gestion mémoire sécurisée
 *
 * Wrappers autour de malloc/free qui font du zeroing
 * pour pas laisser de données sensibles en mémoire.
 */

#ifndef MEMORY_H
#define MEMORY_H

#include "../../include/common.h"

/*
 * Alloue de la mémoire avec zeroing initial.
 * Équivalent à calloc(1, size).
 */
void *secure_alloc(size_t size);

/*
 * Réalloue un buffer.
 * Si new_size est plus petit, le surplus est zéro avant.
 */
void *secure_realloc(void *ptr, size_t old_size, size_t new_size);

/*
 * Libère la mémoire après l'avoir mise à zéro.
 */
void secure_free(void *ptr, size_t size);

/*
 * Met un buffer à zéro de façon sécurisée.
 * Empêche le compilateur d'optimiser l'appel.
 */
void secure_zero(void *ptr, size_t size);

/*
 * Copie sécurisée avec vérification de taille.
 */
int secure_memcpy(void *dest, size_t dest_size, const void *src, size_t count);

#endif /* MEMORY_H */
