/*
 * shell.h - Exécution de commandes shell
 */

#ifndef HANDLER_SHELL_H
#define HANDLER_SHELL_H

#include "../../../include/common.h"

/*
 * Exécute une commande shell et capture l'output.
 *
 * Params:
 *   command - Commande à exécuter
 *   output  - Pointeur vers l'output (alloué par la fonction)
 *   len     - Taille de l'output
 */
int handler_shell_exec(const char *command, char **output, size_t *len);

#endif /* HANDLER_SHELL_H */
