#ifndef DESKTOP_H
#define DESKTOP_H

#include <windows.h>

/*
 * Capture l'écran entier et retourne les données JPEG.
 * quality: 1-100 (qualité JPEG, défaut 50)
 * L'appelant doit libérer outData avec free().
 */
BOOL Desktop_CaptureScreen(BYTE** outData, DWORD* outSize, int quality);

/*
 * Injecte un événement souris.
 * x, y: coordonnées pixel sur l'écran
 * flags: 1=MOVE, 2=LDOWN, 4=LUP, 8=RDOWN, 16=RUP
 */
BOOL Desktop_InjectMouse(int x, int y, DWORD flags);

/*
 * Injecte un événement clavier.
 * vkCode: code de touche virtuelle
 * keyUp: TRUE pour relâchement, FALSE pour appui
 */
BOOL Desktop_InjectKey(WORD vkCode, BOOL keyUp);

#endif // DESKTOP_H
