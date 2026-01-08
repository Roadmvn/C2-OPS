/*
 * xor.c - Implémentation du chiffrement XOR
 */

#include "xor.h"

/* Clé par défaut pour les strings - sera changée par le builder */
static const uint8_t DEFAULT_XOR_KEY[] = {0x41, 0x6e, 0x74, 0x69, 0x47, 0x72,
                                          0x61, 0x76, 0x69, 0x74, 0x79, 0x43,
                                          0x32, 0x46, 0x72, 0x61};

void xor_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
                 size_t key_len) {
  if (!data || !key || data_len == 0 || key_len == 0) {
    return;
  }

  for (size_t i = 0; i < data_len; i++) {
    data[i] ^= key[i % key_len];
  }
}

void xor_string(char *str) {
  if (!str) {
    return;
  }

  size_t len = strlen(str);
  xor_encrypt((uint8_t *)str, len, DEFAULT_XOR_KEY, sizeof(DEFAULT_XOR_KEY));
}
