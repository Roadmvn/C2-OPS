/*
 * xor.h - Chiffrement XOR simple
 *
 * Utilisé pour obfusquer les strings en mémoire.
 * C'est pas du vrai chiffrement, mais ça évite d'avoir
 * des strings en clair dans le binaire.
 */

#ifndef XOR_H
#define XOR_H

#include "../../include/common.h"

/*
 * XOR un buffer avec une clé.
 * L'opération est faite en place.
 *
 * Params:
 *   data     - Buffer à XOR
 *   data_len - Taille du buffer
 *   key      - Clé XOR
 *   key_len  - Taille de la clé
 */
void xor_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
                 size_t key_len);

/*
 * Alias pour decrypt (c'est la même opération).
 */
#define xor_decrypt xor_encrypt

/*
 * XOR une string en place.
 * Utilise la clé par défaut embarquée.
 */
void xor_string(char *str);

#endif /* XOR_H */
