/*
 * aes.c - Implémentation AES-256-CBC
 *
 * Basé sur tiny-aes-c par kokke (domaine public).
 * Adapté pour notre usage avec padding PKCS7.
 * Ref: FIPS 197 (AES Standard)
 */

#include "aes.h"
#include "../utils/memory.h"

/* AES constants */

#define Nb 4  /* Nombre de colonnes (32-bit words) */
#define Nk 8  /* Nombre de mots de 32 bits dans la clé (AES-256) */
#define Nr 14 /* Nombre de rounds (AES-256) */

/* S-Box lookup tables */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

/* Round constant */
static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
                                 0x20, 0x40, 0x80, 0x1b, 0x36};

/* Internal types */
typedef uint8_t state_t[4][4];

typedef struct {
  uint8_t RoundKey[240]; /* Expanded key */
  uint8_t Iv[AES_BLOCK_SIZE];
} aes_ctx_t;

/* AES core operations */

static uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

static void key_expansion(aes_ctx_t *ctx, const uint8_t *key) {
  uint32_t i, j, k;
  uint8_t tempa[4];

  /* Premier round key = la clé elle-même */
  for (i = 0; i < Nk; ++i) {
    ctx->RoundKey[(i * 4) + 0] = key[(i * 4) + 0];
    ctx->RoundKey[(i * 4) + 1] = key[(i * 4) + 1];
    ctx->RoundKey[(i * 4) + 2] = key[(i * 4) + 2];
    ctx->RoundKey[(i * 4) + 3] = key[(i * 4) + 3];
  }

  /* Les autres round keys */
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    k = (i - 1) * 4;
    tempa[0] = ctx->RoundKey[k + 0];
    tempa[1] = ctx->RoundKey[k + 1];
    tempa[2] = ctx->RoundKey[k + 2];
    tempa[3] = ctx->RoundKey[k + 3];

    if (i % Nk == 0) {
      /* RotWord */
      uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = u8tmp;

      /* SubWord */
      tempa[0] = sbox[tempa[0]];
      tempa[1] = sbox[tempa[1]];
      tempa[2] = sbox[tempa[2]];
      tempa[3] = sbox[tempa[3]];

      tempa[0] = tempa[0] ^ Rcon[i / Nk];
    }

    if (i % Nk == 4) {
      tempa[0] = sbox[tempa[0]];
      tempa[1] = sbox[tempa[1]];
      tempa[2] = sbox[tempa[2]];
      tempa[3] = sbox[tempa[3]];
    }

    j = i * 4;
    k = (i - Nk) * 4;
    ctx->RoundKey[j + 0] = ctx->RoundKey[k + 0] ^ tempa[0];
    ctx->RoundKey[j + 1] = ctx->RoundKey[k + 1] ^ tempa[1];
    ctx->RoundKey[j + 2] = ctx->RoundKey[k + 2] ^ tempa[2];
    ctx->RoundKey[j + 3] = ctx->RoundKey[k + 3] ^ tempa[3];
  }
}

static void add_round_key(uint8_t round, state_t *state,
                          const uint8_t *RoundKey) {
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static void sub_bytes(state_t *state) {
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      (*state)[j][i] = sbox[(*state)[j][i]];
    }
  }
}

static void inv_sub_bytes(state_t *state) {
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      (*state)[j][i] = rsbox[(*state)[j][i]];
    }
  }
}

static void shift_rows(state_t *state) {
  uint8_t temp;

  /* Row 1 */
  temp = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  /* Row 2 */
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  /* Row 3 */
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static void inv_shift_rows(state_t *state) {
  uint8_t temp;

  /* Row 1 */
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  /* Row 2 */
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  /* Row 3 */
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}

static void mix_columns(state_t *state) {
  uint8_t Tmp, Tm, t;
  for (uint8_t i = 0; i < 4; ++i) {
    t = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
    Tm = (*state)[i][0] ^ (*state)[i][1];
    Tm = xtime(Tm);
    (*state)[i][0] ^= Tm ^ Tmp;
    Tm = (*state)[i][1] ^ (*state)[i][2];
    Tm = xtime(Tm);
    (*state)[i][1] ^= Tm ^ Tmp;
    Tm = (*state)[i][2] ^ (*state)[i][3];
    Tm = xtime(Tm);
    (*state)[i][2] ^= Tm ^ Tmp;
    Tm = (*state)[i][3] ^ t;
    Tm = xtime(Tm);
    (*state)[i][3] ^= Tm ^ Tmp;
  }
}

#define Multiply(x, y)                                                         \
  (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^                                 \
   ((y >> 2 & 1) * xtime(xtime(x))) ^                                          \
   ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^                                   \
   ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

static void inv_mix_columns(state_t *state) {
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i) {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^
                     Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^
                     Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^
                     Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^
                     Multiply(d, 0x0e);
  }
}

static void cipher(state_t *state, const uint8_t *RoundKey) {
  uint8_t round = 0;

  add_round_key(0, state, RoundKey);

  for (round = 1; round < Nr; ++round) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(round, state, RoundKey);
  }

  sub_bytes(state);
  shift_rows(state);
  add_round_key(Nr, state, RoundKey);
}

static void inv_cipher(state_t *state, const uint8_t *RoundKey) {
  uint8_t round = 0;

  add_round_key(Nr, state, RoundKey);

  for (round = (Nr - 1); round > 0; --round) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(round, state, RoundKey);
    inv_mix_columns(state);
  }

  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(0, state, RoundKey);
}

static void xor_with_iv(uint8_t *buf, const uint8_t *Iv) {
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; ++i) {
    buf[i] ^= Iv[i];
  }
}

/* Public API */

int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t **ciphertext,
                size_t *ciphertext_len) {
  if (!plaintext || !key || !iv || !ciphertext || !ciphertext_len) {
    return STATUS_FAILURE;
  }

  /* Calcule la taille avec padding PKCS7 */
  size_t padded_len = ((plaintext_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

  /* Alloue le buffer de sortie */
  uint8_t *output = (uint8_t *)secure_alloc(padded_len);
  if (!output) {
    return STATUS_NO_MEMORY;
  }

  /* Copie les données et ajoute le padding */
  memcpy(output, plaintext, plaintext_len);
  uint8_t padding_value = (uint8_t)(padded_len - plaintext_len);
  for (size_t i = plaintext_len; i < padded_len; i++) {
    output[i] = padding_value;
  }

  /* Init AES context */
  aes_ctx_t ctx;
  memcpy(ctx.Iv, iv, AES_BLOCK_SIZE);
  key_expansion(&ctx, key);

  /* Chiffre en mode CBC */
  uint8_t *ptr = output;
  for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
    xor_with_iv(ptr, ctx.Iv);
    cipher((state_t *)ptr, ctx.RoundKey);
    memcpy(ctx.Iv, ptr, AES_BLOCK_SIZE);
    ptr += AES_BLOCK_SIZE;
  }

  *ciphertext = output;
  *ciphertext_len = padded_len;

  /* Efface le contexte */
  SecureZeroMemory(&ctx, sizeof(ctx));

  return STATUS_SUCCESS;
}

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t **plaintext,
                size_t *plaintext_len) {
  if (!ciphertext || !key || !iv || !plaintext || !plaintext_len) {
    return STATUS_FAILURE;
  }

  /* La taille doit être un multiple de 16 */
  if (ciphertext_len == 0 || ciphertext_len % AES_BLOCK_SIZE != 0) {
    return STATUS_CRYPTO_ERROR;
  }

  /* Alloue le buffer de sortie */
  uint8_t *output = (uint8_t *)secure_alloc(ciphertext_len);
  if (!output) {
    return STATUS_NO_MEMORY;
  }

  memcpy(output, ciphertext, ciphertext_len);

  /* Init AES context */
  aes_ctx_t ctx;
  memcpy(ctx.Iv, iv, AES_BLOCK_SIZE);
  key_expansion(&ctx, key);

  /* Déchiffre en mode CBC */
  uint8_t next_iv[AES_BLOCK_SIZE];
  uint8_t *ptr = output;

  for (size_t i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
    memcpy(next_iv, ptr, AES_BLOCK_SIZE);
    inv_cipher((state_t *)ptr, ctx.RoundKey);
    xor_with_iv(ptr, ctx.Iv);
    memcpy(ctx.Iv, next_iv, AES_BLOCK_SIZE);
    ptr += AES_BLOCK_SIZE;
  }

  /* Enlève le padding PKCS7 */
  uint8_t padding_value = output[ciphertext_len - 1];
  if (padding_value > AES_BLOCK_SIZE || padding_value == 0) {
    secure_free(output, ciphertext_len);
    return STATUS_CRYPTO_ERROR;
  }

  /* Vérifie le padding */
  for (size_t i = ciphertext_len - padding_value; i < ciphertext_len; i++) {
    if (output[i] != padding_value) {
      secure_free(output, ciphertext_len);
      return STATUS_CRYPTO_ERROR;
    }
  }

  *plaintext = output;
  *plaintext_len = ciphertext_len - padding_value;

  SecureZeroMemory(&ctx, sizeof(ctx));
  SecureZeroMemory(next_iv, sizeof(next_iv));

  return STATUS_SUCCESS;
}

void aes_generate_iv(uint8_t *iv) {
  if (!iv)
    return;

  /* Utilise les compteurs de performance pour plus d'entropie */
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);

  /* Seed basé sur plusieurs sources */
  srand(
      (unsigned int)(counter.LowPart ^ GetTickCount() ^ GetCurrentProcessId()));

  /* Génère 16 bytes aléatoires */
  for (int i = 0; i < AES_BLOCK_SIZE; i++) {
    iv[i] = (uint8_t)(rand() & 0xFF);
  }

  /* XOR avec le timestamp pour plus de variabilité */
  DWORD tick = GetTickCount();
  for (int i = 0; i < 4; i++) {
    iv[i] ^= (uint8_t)(tick >> (i * 8));
  }
}
