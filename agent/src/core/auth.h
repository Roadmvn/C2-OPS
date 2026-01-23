#ifndef AUTH_H
#define AUTH_H

#include <windows.h>

/*
 * Répond à un challenge d'authentification.
 * Calcule HMAC-SHA256(buildKey, challenge) et retourne le résultat en hex.
 */
BOOL Auth_RespondToChallenge(const char* challengeHex, char* responseHex, DWORD responseHexSize);

/*
 * Stocke le token d'authentification reçu du serveur.
 */
void Auth_SetToken(const char* token);

/*
 * Retourne le token d'authentification actuel.
 */
const char* Auth_GetToken(void);

/*
 * Vérifie si l'agent est authentifié.
 */
BOOL Auth_IsAuthenticated(void);

/*
 * Réinitialise l'état d'authentification.
 */
void Auth_Reset(void);

/*
 * Génère un Agent ID unique basé sur le matériel.
 */
BOOL Auth_GenerateAgentID(char* agentID, DWORD agentIDSize);

#endif // AUTH_H
