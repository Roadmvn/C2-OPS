/*
 * aes.h - Chiffrement AES-256-CBC
 *
 * Implémentation basée sur tiny-aes-c, adaptée pour nos besoins.
 * On utilise AES-256 en mode CBC avec padding PKCS7.
 */

#ifndef AES_H
#define AES_H

#include "../../include/common.h"

/* Taille de bloc AES */
#define AES_BLOCK_SIZE 16

/* Taille de clé AES-256 */
#define AES_KEY_SIZE 32

/* ============================================================================
 * Prototypes
 * ============================================================================
 */

/*
 * Chiffre des données avec AES-256-CBC.
 *
 * Params:
 *   plaintext     - Données en clair
 *   plaintext_len - Taille des données
 *   key           - Clé AES-256 (32 bytes)
 *   iv            - Vecteur d'init (16 bytes)
 *   ciphertext    - Pointeur vers le buffer chiffré (alloué par la fonction)
 *   ciphertext_len- Taille du buffer chiffré
 *
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 * L'appelant doit libérer ciphertext avec secure_free().
 */
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t **ciphertext,
                size_t *ciphertext_len);

/*
 * Déchiffre des données avec AES-256-CBC.
 *
 * Params:
 *   ciphertext    - Données chiffrées
 *   ciphertext_len- Taille des données chiffrées
 *   key           - Clé AES-256 (32 bytes)
 *   iv            - Vecteur d'init (16 bytes)
 *   plaintext     - Pointeur vers le buffer déchiffré
 *   plaintext_len - Taille du buffer déchiffré
 *
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 */
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t **plaintext,
                size_t *plaintext_len);

/*
 * Génère un IV aléatoire de 16 bytes.
 */
void aes_generate_iv(uint8_t *iv);

#endif /* AES_H */
