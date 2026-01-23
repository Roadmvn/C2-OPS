#ifndef SOCKS5_H
#define SOCKS5_H

#include <windows.h>

/*
 * Démarre le serveur SOCKS5 sur le port spécifié.
 * port: port d'écoute (0 = choix automatique)
 * Retourne le port effectif ou 0 en cas d'erreur.
 */
USHORT Socks5_Start(USHORT port);

/*
 * Arrête le serveur SOCKS5.
 */
void Socks5_Stop(void);

/*
 * Vérifie si le proxy est actif.
 */
BOOL Socks5_IsRunning(void);

/*
 * Retourne le port d'écoute du proxy.
 */
USHORT Socks5_GetPort(void);

#endif // SOCKS5_H
