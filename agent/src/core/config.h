/*
 * config.h - Gestion de la configuration de l'agent
 *
 * La config est embarquée dans le binaire de façon chiffrée.
 * Elle contient l'URL du C2, le sleep time, le jitter, etc.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "common.h"

/* ============================================================================
 * Structure de configuration de l'agent
 * ============================================================================
 */
typedef struct {
  char agent_id[64];        /* UUID de l'agent, généré au premier run */
  char c2_url[MAX_URL_LEN]; /* URL du serveur C2 */
  char user_agent[256];     /* User-Agent pour les requêtes HTTP */
  DWORD sleep_ms;           /* Temps de sleep entre les callbacks */
  int jitter_pct;           /* Pourcentage de jitter (0-50) */
  uint8_t aes_key[32];      /* Clé AES-256 pour le chiffrement */
  uint8_t aes_iv[16];       /* IV pour AES-CBC */
  bool use_https;           /* Utiliser HTTPS ou HTTP */
  int max_retries;          /* Nombre de retries en cas d'échec */
  bool debug_mode;          /* Mode debug (plus de logs) */
} agent_config_t;

/* ============================================================================
 * Prototypes
 * ============================================================================
 */

/*
 * Initialise la configuration.
 * Déchiffre la config embarquée et remplit la structure.
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 */
int config_init(agent_config_t *config);

/*
 * Met à jour le sleep time.
 * Appelé quand le serveur envoie une commande SLEEP.
 */
void config_set_sleep(agent_config_t *config, DWORD sleep_ms);

/*
 * Met à jour le jitter.
 */
void config_set_jitter(agent_config_t *config, int jitter_pct);

/*
 * Génère l'ID de l'agent si pas encore fait.
 * L'ID est persisté quelque part pour pas changer à chaque restart.
 */
void config_generate_agent_id(agent_config_t *config);

/*
 * Libère les ressources de la config.
 */
void config_cleanup(agent_config_t *config);

/* ============================================================================
 * Config par défaut - ces valeurs sont chiffrées à la compilation
 * ============================================================================
 */

/*
 * Note: Dans un vrai scénario, ces valeurs seraient injectées par le
 * générateur de payload côté serveur. Ici on met des valeurs par défaut
 * pour le développement.
 */
#define DEFAULT_C2_URL "https://127.0.0.1:443"
#define DEFAULT_USER_AGENT                                                     \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

#endif /* CONFIG_H */
