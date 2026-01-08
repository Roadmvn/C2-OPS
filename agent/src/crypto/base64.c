/*
 * base64.c - Implémentation Base64
 *
 * Encodage et décodage base64 standard (RFC 4648).
 */

#include "base64.h"

/* Table d'encodage */
static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Table de décodage (initialisée au premier appel) */
static int B64_DECODE_TABLE[256] = {0};
static bool b64_table_initialized = false;

/* Initialise la table de décodage */
static void init_decode_table(void) {
  if (b64_table_initialized)
    return;

  /* -1 = caractère invalide */
  for (int i = 0; i < 256; i++) {
    B64_DECODE_TABLE[i] = -1;
  }

  /* Remplit avec les valeurs valides */
  for (int i = 0; i < 64; i++) {
    B64_DECODE_TABLE[(unsigned char)B64_TABLE[i]] = i;
  }

  /* '=' est un padding valide mais vaut 0 */
  B64_DECODE_TABLE['='] = 0;

  b64_table_initialized = true;
}

size_t base64_encoded_size(size_t input_len) {
  /* Base64 produit 4 caractères pour chaque 3 bytes */
  return ((input_len + 2) / 3) * 4 + 1; /* +1 pour le null terminator */
}

size_t base64_decoded_size(const char *b64_str, size_t str_len) {
  if (!b64_str)
    return 0;

  if (str_len == 0) {
    str_len = strlen(b64_str);
  }

  if (str_len == 0)
    return 0;

  /* Approximation: 3 bytes pour chaque 4 caractères */
  size_t size = (str_len / 4) * 3;

  /* Ajuste pour le padding */
  if (str_len >= 1 && b64_str[str_len - 1] == '=')
    size--;
  if (str_len >= 2 && b64_str[str_len - 2] == '=')
    size--;

  return size;
}

char *base64_encode(const uint8_t *data, size_t data_len) {
  if (!data || data_len == 0) {
    return NULL;
  }

  size_t out_len = base64_encoded_size(data_len);
  char *output = (char *)malloc(out_len);
  if (!output) {
    return NULL;
  }

  size_t i, j;
  for (i = 0, j = 0; i < data_len;) {
    /* Récupère 3 bytes (ou moins à la fin) */
    uint32_t octet_a = i < data_len ? data[i++] : 0;
    uint32_t octet_b = i < data_len ? data[i++] : 0;
    uint32_t octet_c = i < data_len ? data[i++] : 0;

    /* Combine en un uint32 */
    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    /* Extrait 4 caractères base64 */
    output[j++] = B64_TABLE[(triple >> 18) & 0x3F];
    output[j++] = B64_TABLE[(triple >> 12) & 0x3F];
    output[j++] = B64_TABLE[(triple >> 6) & 0x3F];
    output[j++] = B64_TABLE[triple & 0x3F];
  }

  /* Ajoute le padding si nécessaire */
  size_t mod = data_len % 3;
  if (mod > 0) {
    output[j - 1] = '=';
    if (mod == 1) {
      output[j - 2] = '=';
    }
  }

  output[j] = '\0';

  return output;
}

uint8_t *base64_decode(const char *b64_str, size_t str_len,
                       size_t *output_len) {
  if (!b64_str || !output_len) {
    return NULL;
  }

  init_decode_table();

  if (str_len == 0) {
    str_len = strlen(b64_str);
  }

  if (str_len == 0 || str_len % 4 != 0) {
    return NULL; /* Base64 doit être un multiple de 4 */
  }

  size_t out_len = base64_decoded_size(b64_str, str_len);
  uint8_t *output = (uint8_t *)malloc(out_len + 1); /* +1 pour sécurité */
  if (!output) {
    return NULL;
  }

  size_t i, j;
  for (i = 0, j = 0; i < str_len;) {
    /* Décode 4 caractères en 3 bytes */
    int a = B64_DECODE_TABLE[(unsigned char)b64_str[i++]];
    int b = B64_DECODE_TABLE[(unsigned char)b64_str[i++]];
    int c = B64_DECODE_TABLE[(unsigned char)b64_str[i++]];
    int d = B64_DECODE_TABLE[(unsigned char)b64_str[i++]];

    /* Vérifie les caractères invalides */
    if (a < 0 || b < 0 || c < 0 || d < 0) {
      free(output);
      return NULL;
    }

    /* Reconstruit les 3 bytes */
    uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;

    if (j < out_len)
      output[j++] = (triple >> 16) & 0xFF;
    if (j < out_len)
      output[j++] = (triple >> 8) & 0xFF;
    if (j < out_len)
      output[j++] = triple & 0xFF;
  }

  *output_len = out_len;
  return output;
}
