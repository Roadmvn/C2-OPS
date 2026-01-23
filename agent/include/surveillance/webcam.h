/*
 * webcam.h - Module de capture webcam
 */

#ifndef WEBCAM_H
#define WEBCAM_H

#include "../common.h"

/*
 * Capture une image depuis la webcam
 * Retourne un buffer BMP alloué dynamiquement
 * 
 * @param data Pointeur pour recevoir les données de l'image
 * @param size Pointeur pour recevoir la taille des données
 * @return TRUE si capture réussie, FALSE sinon
 */
bool Webcam_CaptureSnapshot(BYTE** data, DWORD* size);

#endif /* WEBCAM_H */
