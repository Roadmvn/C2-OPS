#ifndef SCANNER_H
#define SCANNER_H

#include <windows.h>

/*
 * Scanne les ports communs d'une cible.
 * target: IP ou hostname
 * outJson: résultat JSON avec les ports ouverts
 */
BOOL Scanner_ScanPorts(const char* target, char** outJson);

/*
 * Scanne une plage de ports personnalisée.
 */
BOOL Scanner_ScanRange(const char* target, USHORT startPort, USHORT endPort, char** outJson);

/*
 * Vérifie si un hôte est accessible.
 */
BOOL Scanner_IsHostUp(const char* target, BOOL* isUp);

#endif // SCANNER_H
