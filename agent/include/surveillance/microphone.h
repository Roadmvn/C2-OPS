#ifndef MICROPHONE_H
#define MICROPHONE_H

#include <windows.h>

/*
 * Capture le microphone pendant 'seconds' secondes.
 * Retourne un buffer WAV complet (avec header).
 * L'appelant doit libérer le buffer.
 */
BYTE* Microphone_Record(int seconds, DWORD* outSize);

#endif // MICROPHONE_H
