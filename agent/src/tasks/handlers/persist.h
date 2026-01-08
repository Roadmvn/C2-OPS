/*
 * persist.h - Mécanismes de persistence
 */

#ifndef HANDLER_PERSIST_H
#define HANDLER_PERSIST_H

#include "../../../include/common.h"

/*
 * Ajoute de la persistence.
 *
 * Types supportés:
 *   - "registry" : Clé Run dans le registre
 *   - "schtask"  : Tâche planifiée
 */
int handler_persist_add(const char *type);

/*
 * Supprime la persistence.
 */
int handler_persist_remove(const char *type);

/*
 * Liste les méthodes de persistence actives.
 */
int handler_persist_list(char **output, size_t *len);

#endif /* HANDLER_PERSIST_H */
