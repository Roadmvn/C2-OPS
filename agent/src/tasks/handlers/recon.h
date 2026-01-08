/*
 * recon.h - Reconnaissance système
 */

#ifndef HANDLER_RECON_H
#define HANDLER_RECON_H

#include "../../../include/common.h"

/*
 * Retourne les infos utilisateur (whoami).
 */
int handler_recon_whoami(char **output, size_t *len);

/*
 * Retourne les infos système complètes.
 */
int handler_recon_sysinfo(char **output, size_t *len);

/*
 * Liste les interfaces réseau et IPs.
 */
int handler_recon_ipconfig(char **output, size_t *len);

#endif /* HANDLER_RECON_H */
