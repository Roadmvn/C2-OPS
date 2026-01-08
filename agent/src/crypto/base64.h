/*
 * base64.h - Encodage/décodage Base64
 *
 * Utilisé pour encoder les données binaires avant le transport HTTP.
 */

#ifndef BASE64_H
#define BASE64_H

#include "../../include/common.h"

/*
 * Encode des données en base64.
 *
 * Params:
 *   data     - Données à encoder
 *   data_len - Taille des données
 *
 * Retourne une string allouée (à libérer avec free()) ou NULL en cas d'erreur.
 */
char *base64_encode(const uint8_t *data, size_t data_len);

/*
 * Décode une string base64.
 *
 * Params:
 *   b64_str    - String base64 à décoder
 *   str_len    - Taille de la string (peut être 0 pour strlen)
 *   output_len - Pointeur pour stocker la taille du résultat
 *
 * Retourne un buffer alloué (à libérer avec free()) ou NULL en cas d'erreur.
 */
uint8_t *base64_decode(const char *b64_str, size_t str_len, size_t *output_len);

/*
 * Calcule la taille du buffer nécessaire pour encoder en base64.
 */
size_t base64_encoded_size(size_t input_len);

/*
 * Calcule la taille du buffer décodé (approximation haute).
 */
size_t base64_decoded_size(const char *b64_str, size_t str_len);

#endif /* BASE64_H */
