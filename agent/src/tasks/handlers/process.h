/*
 * process.h - Opérations sur les processus
 */

#ifndef HANDLER_PROCESS_H
#define HANDLER_PROCESS_H

#include "../../../include/common.h"

/*
 * Liste les processus en cours.
 */
int handler_process_list(char **output, size_t *len);

/*
 * Termine un processus par son PID.
 */
int handler_process_kill(DWORD pid);

/*
 * Récupère des infos sur un processus.
 */
int handler_process_info(DWORD pid, char **output, size_t *len);

#endif /* HANDLER_PROCESS_H */
