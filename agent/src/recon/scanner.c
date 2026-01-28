/*
 * scanner.c - Scanner de vulnérabilités
 *
 * Reconnaissance réseau et identification de cibles :
 * - Port scanning (TCP connect)
 * - Service fingerprinting
 * - Détection de vulnérabilités connues
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#include "../../include/common.h"

/* Config */

#define SCAN_TIMEOUT_MS     2000
#define MAX_SCAN_RESULTS    256

/* Ports communs à scanner */
static const USHORT COMMON_PORTS[] = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    443,   // HTTPS
    445,   // SMB
    1433,  // MSSQL
    1521,  // Oracle
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis
    8080,  // HTTP Alt
    8443,  // HTTPS Alt
    27017, // MongoDB
    0      // Fin de liste
};

/* Services connus par port */
typedef struct {
    USHORT port;
    const char* service;
    const char* description;
} ServiceInfo;

static const ServiceInfo KNOWN_SERVICES[] = {
    {21,    "FTP",      "File Transfer Protocol"},
    {22,    "SSH",      "Secure Shell"},
    {23,    "Telnet",   "Telnet (insecure)"},
    {25,    "SMTP",     "Simple Mail Transfer"},
    {53,    "DNS",      "Domain Name System"},
    {80,    "HTTP",     "Web Server"},
    {110,   "POP3",     "Post Office Protocol"},
    {135,   "MSRPC",    "Microsoft RPC"},
    {139,   "NetBIOS",  "NetBIOS Session"},
    {143,   "IMAP",     "Internet Message Access"},
    {443,   "HTTPS",    "Web Server (SSL)"},
    {445,   "SMB",      "Server Message Block"},
    {1433,  "MSSQL",    "Microsoft SQL Server"},
    {1521,  "Oracle",   "Oracle Database"},
    {3306,  "MySQL",    "MySQL Database"},
    {3389,  "RDP",      "Remote Desktop"},
    {5432,  "Postgres", "PostgreSQL Database"},
    {5900,  "VNC",      "Virtual Network Computing"},
    {6379,  "Redis",    "Redis Cache"},
    {8080,  "HTTP-Alt", "Alternate HTTP"},
    {8443,  "HTTPS-Alt","Alternate HTTPS"},
    {27017, "MongoDB",  "MongoDB Database"},
    {0, NULL, NULL}
};

/* Data structures */

typedef struct {
    USHORT port;
    BOOL open;
    char service[32];
    char banner[256];
} PortResult;

typedef struct {
    char target[256];
    PortResult ports[MAX_SCAN_RESULTS];
    int portCount;
    DWORD scanTime;
} ScanResult;

/* Helpers */

/* Initialise Winsock */
static BOOL InitWinsock(void) {
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

/* Trouve le nom du service par port */
static const char* GetServiceName(USHORT port) {
    for (int i = 0; KNOWN_SERVICES[i].port != 0; i++) {
        if (KNOWN_SERVICES[i].port == port) {
            return KNOWN_SERVICES[i].service;
        }
    }
    return "Unknown";
}

/* Vérifie si un port est ouvert (TCP connect) */
static BOOL IsPortOpen(const char* host, USHORT port, char* banner, DWORD bannerSize) {
    if (banner) banner[0] = '\0';
    
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%u", port);
    
    if (getaddrinfo(host, portStr, &hints, &result) != 0) {
        return FALSE;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        return FALSE;
    }
    
    // Timeout pour connect
    DWORD timeout = SCAN_TIMEOUT_MS;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Mode non-bloquant pour le connect
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    int connectResult = connect(sock, result->ai_addr, (int)result->ai_addrlen);
    
    if (connectResult == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        // Attend la connexion
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sock, &writeSet);
        
        struct timeval tv;
        tv.tv_sec = SCAN_TIMEOUT_MS / 1000;
        tv.tv_usec = (SCAN_TIMEOUT_MS % 1000) * 1000;
        
        if (select(0, NULL, &writeSet, NULL, &tv) <= 0) {
            closesocket(sock);
            freeaddrinfo(result);
            return FALSE;
        }
    }
    
    // Repasse en mode bloquant
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    
    // Tente de récupérer un banner
    if (banner && bannerSize > 0) {
        // Timeout court pour le banner
        timeout = 500;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        
        int received = recv(sock, banner, bannerSize - 1, 0);
        if (received > 0) {
            banner[received] = '\0';
            // Nettoie les caractères non imprimables
            for (int i = 0; i < received; i++) {
                if (banner[i] < 32 || banner[i] > 126) {
                    banner[i] = ' ';
                }
            }
        }
    }
    
    closesocket(sock);
    freeaddrinfo(result);
    return TRUE;
}

/* Public API */

/*
 * Scanne les ports communs d'une cible.
 * target: IP ou hostname
 * Retourne un JSON avec les résultats.
 */
BOOL Scanner_ScanPorts(const char* target, char** outJson) {
    if (!target || !outJson) return FALSE;
    *outJson = NULL;
    
    if (!InitWinsock()) return FALSE;
    
    DWORD startTime = GetTickCount();
    ScanResult result = {0};
    strncpy(result.target, target, sizeof(result.target) - 1);
    
    // Scanne les ports communs
    for (int i = 0; COMMON_PORTS[i] != 0 && result.portCount < MAX_SCAN_RESULTS; i++) {
        USHORT port = COMMON_PORTS[i];
        char banner[256] = {0};
        
        if (IsPortOpen(target, port, banner, sizeof(banner))) {
            PortResult* pr = &result.ports[result.portCount++];
            pr->port = port;
            pr->open = TRUE;
            strncpy(pr->service, GetServiceName(port), sizeof(pr->service) - 1);
            strncpy(pr->banner, banner, sizeof(pr->banner) - 1);
        }
    }
    
    result.scanTime = GetTickCount() - startTime;
    
    // Construit le JSON
    size_t jsonSize = 4096 + (result.portCount * 512);
    char* json = (char*)malloc(jsonSize);
    if (!json) {
        WSACleanup();
        return FALSE;
    }
    
    int offset = snprintf(json, jsonSize,
        "{\n"
        "  \"target\": \"%s\",\n"
        "  \"scan_time_ms\": %lu,\n"
        "  \"open_ports\": %d,\n"
        "  \"ports\": [\n",
        result.target,
        result.scanTime,
        result.portCount);
    
    for (int i = 0; i < result.portCount && offset < (int)jsonSize - 200; i++) {
        PortResult* pr = &result.ports[i];
        
        // Échappe le banner pour JSON
        char escapedBanner[512] = {0};
        int j = 0;
        for (const char* p = pr->banner; *p && j < sizeof(escapedBanner) - 2; p++) {
            if (*p == '"' || *p == '\\') {
                escapedBanner[j++] = '\\';
            }
            escapedBanner[j++] = *p;
        }
        
        offset += snprintf(json + offset, jsonSize - offset,
            "    {\"port\": %u, \"service\": \"%s\", \"banner\": \"%s\"}%s\n",
            pr->port,
            pr->service,
            escapedBanner,
            i < result.portCount - 1 ? "," : "");
    }
    
    snprintf(json + offset, jsonSize - offset, "  ]\n}");
    
    WSACleanup();
    *outJson = json;
    return TRUE;
}

/*
 * Scanne une plage de ports personnalisée.
 */
BOOL Scanner_ScanRange(const char* target, USHORT startPort, USHORT endPort, char** outJson) {
    if (!target || !outJson || startPort > endPort) return FALSE;
    *outJson = NULL;
    
    if (!InitWinsock()) return FALSE;
    
    DWORD startTime = GetTickCount();
    ScanResult result = {0};
    strncpy(result.target, target, sizeof(result.target) - 1);
    
    // Scanne la plage
    for (USHORT port = startPort; port <= endPort && result.portCount < MAX_SCAN_RESULTS; port++) {
        char banner[256] = {0};
        
        if (IsPortOpen(target, port, banner, sizeof(banner))) {
            PortResult* pr = &result.ports[result.portCount++];
            pr->port = port;
            pr->open = TRUE;
            strncpy(pr->service, GetServiceName(port), sizeof(pr->service) - 1);
            strncpy(pr->banner, banner, sizeof(pr->banner) - 1);
        }
    }
    
    result.scanTime = GetTickCount() - startTime;
    
    // Construit le JSON (même format qu'au-dessus)
    size_t jsonSize = 4096 + (result.portCount * 512);
    char* json = (char*)malloc(jsonSize);
    if (!json) {
        WSACleanup();
        return FALSE;
    }
    
    int offset = snprintf(json, jsonSize,
        "{\n"
        "  \"target\": \"%s\",\n"
        "  \"range\": \"%u-%u\",\n"
        "  \"scan_time_ms\": %lu,\n"
        "  \"open_ports\": %d,\n"
        "  \"ports\": [\n",
        result.target,
        startPort, endPort,
        result.scanTime,
        result.portCount);
    
    for (int i = 0; i < result.portCount && offset < (int)jsonSize - 200; i++) {
        PortResult* pr = &result.ports[i];
        
        offset += snprintf(json + offset, jsonSize - offset,
            "    {\"port\": %u, \"service\": \"%s\"}%s\n",
            pr->port,
            pr->service,
            i < result.portCount - 1 ? "," : "");
    }
    
    snprintf(json + offset, jsonSize - offset, "  ]\n}");
    
    WSACleanup();
    *outJson = json;
    return TRUE;
}

/*
 * Ping simple (ICMP) pour vérifier si un hôte est up.
 * Note: ICMP nécessite généralement des privilèges admin.
 * On utilise une alternative TCP (connect sur port 80/443).
 */
BOOL Scanner_IsHostUp(const char* target, BOOL* isUp) {
    if (!target || !isUp) return FALSE;
    *isUp = FALSE;
    
    if (!InitWinsock()) return FALSE;
    
    // Tente de se connecter sur quelques ports communs
    USHORT checkPorts[] = {80, 443, 22, 445, 0};
    
    for (int i = 0; checkPorts[i] != 0; i++) {
        if (IsPortOpen(target, checkPorts[i], NULL, 0)) {
            *isUp = TRUE;
            break;
        }
    }
    
    WSACleanup();
    return TRUE;
}
