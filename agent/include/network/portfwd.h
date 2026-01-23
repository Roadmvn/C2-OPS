#ifndef PORTFWD_H
#define PORTFWD_H

#include <windows.h>

/*
 * Initialise le module port forward.
 */
void PortFwd_Init(void);

/*
 * Crée un port forward local → distant.
 * localPort: port d'écoute local (0 = choix automatique)
 * destHost: hôte destination
 * destPort: port destination
 * Retourne l'ID du forward ou 0 en cas d'erreur.
 */
int PortFwd_Create(USHORT localPort, const char* destHost, USHORT destPort);

/*
 * Supprime un port forward.
 */
BOOL PortFwd_Remove(int id);

/*
 * Liste les port forwards actifs.
 * Retourne un JSON avec les infos.
 */
BOOL PortFwd_List(char** outJson);

/*
 * Cleanup du module.
 */
void PortFwd_Cleanup(void);

#endif // PORTFWD_H
