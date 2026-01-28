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
#define PRIVESC_MAX_SERVICES 512

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
 * Check if host is up using TCP connect
 */
BOOL Scanner_IsHostUp(const char* target, BOOL* isUp) {
    if (!target || !isUp) return FALSE;
    *isUp = FALSE;
    
    if (!InitWinsock()) return FALSE;
    
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

/* =========================================================================
 * Privilege Escalation Checks
 * ========================================================================= */

/* Check for dangerous privileges */
static BOOL CheckPrivilege(HANDLE hToken, const char* privName, BOOL* hasPriv) {
    *hasPriv = FALSE;
    
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privName, &luid)) {
        return FALSE;
    }
    
    PRIVILEGE_SET privSet;
    privSet.PrivilegeCount = 1;
    privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privSet.Privilege[0].Luid = luid;
    privSet.Privilege[0].Attributes = 0;
    
    BOOL result = FALSE;
    if (PrivilegeCheck(hToken, &privSet, &result)) {
        *hasPriv = result;
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Check for exploitable privileges (SeImpersonate, SeAssignPrimaryToken, etc.)
 */
BOOL Scanner_CheckPrivileges(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    
    // Privileges to check
    struct {
        const char* name;
        const char* exploit;
        BOOL found;
    } privChecks[] = {
        {"SeImpersonatePrivilege", "Potato attacks (JuicyPotato, PrintSpoofer)", FALSE},
        {"SeAssignPrimaryTokenPrivilege", "Token manipulation", FALSE},
        {"SeBackupPrivilege", "Read any file (backup)", FALSE},
        {"SeRestorePrivilege", "Write any file (restore)", FALSE},
        {"SeDebugPrivilege", "Debug any process, dump LSASS", FALSE},
        {"SeTakeOwnershipPrivilege", "Take ownership of objects", FALSE},
        {"SeLoadDriverPrivilege", "Load kernel driver", FALSE},
        {"SeCreateTokenPrivilege", "Create tokens", FALSE},
        {NULL, NULL, FALSE}
    };
    
    int vulnCount = 0;
    for (int i = 0; privChecks[i].name != NULL; i++) {
        CheckPrivilege(hToken, privChecks[i].name, &privChecks[i].found);
        if (privChecks[i].found) vulnCount++;
    }
    
    CloseHandle(hToken);
    
    // Build JSON
    char* json = (char*)malloc(4096);
    if (!json) return FALSE;
    
    int offset = snprintf(json, 4096,
        "{\n"
        "  \"check\": \"privileges\",\n"
        "  \"exploitable_count\": %d,\n"
        "  \"privileges\": [\n", vulnCount);
    
    BOOL first = TRUE;
    for (int i = 0; privChecks[i].name != NULL; i++) {
        if (privChecks[i].found) {
            offset += snprintf(json + offset, 4096 - offset,
                "%s    {\"name\": \"%s\", \"exploit\": \"%s\"}",
                first ? "" : ",\n",
                privChecks[i].name, privChecks[i].exploit);
            first = FALSE;
        }
    }
    
    snprintf(json + offset, 4096 - offset, "\n  ]\n}");
    
    *outJson = json;
    return TRUE;
}

/*
 * Check for unquoted service paths
 */
BOOL Scanner_CheckUnquotedPaths(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    HKEY hServicesKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 
                      0, KEY_READ, &hServicesKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    
    char* json = (char*)malloc(32768);
    if (!json) {
        RegCloseKey(hServicesKey);
        return FALSE;
    }
    
    int offset = snprintf(json, 32768,
        "{\n"
        "  \"check\": \"unquoted_service_paths\",\n"
        "  \"services\": [\n");
    
    int vulnCount = 0;
    char serviceName[256];
    DWORD index = 0;
    DWORD nameLen = sizeof(serviceName);
    
    while (RegEnumKeyExA(hServicesKey, index++, serviceName, &nameLen, 
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        nameLen = sizeof(serviceName);
        
        HKEY hServiceKey;
        if (RegOpenKeyExA(hServicesKey, serviceName, 0, KEY_READ, &hServiceKey) == ERROR_SUCCESS) {
            char imagePath[1024] = {0};
            DWORD pathLen = sizeof(imagePath);
            DWORD type;
            
            if (RegQueryValueExA(hServiceKey, "ImagePath", NULL, &type, 
                                 (LPBYTE)imagePath, &pathLen) == ERROR_SUCCESS) {
                // Check if path contains spaces and is not quoted
                if (strchr(imagePath, ' ') != NULL && imagePath[0] != '"') {
                    // Check if it's not a system path
                    if (_strnicmp(imagePath, "\\SystemRoot", 11) != 0 &&
                        _strnicmp(imagePath, "system32", 8) != 0) {
                        
                        // Escape for JSON
                        char escaped[2048] = {0};
                        int j = 0;
                        for (const char* p = imagePath; *p && j < 2000; p++) {
                            if (*p == '\\' || *p == '"') escaped[j++] = '\\';
                            escaped[j++] = *p;
                        }
                        
                        if (vulnCount > 0) {
                            offset += snprintf(json + offset, 32768 - offset, ",\n");
                        }
                        offset += snprintf(json + offset, 32768 - offset,
                            "    {\"service\": \"%s\", \"path\": \"%s\"}",
                            serviceName, escaped);
                        vulnCount++;
                    }
                }
            }
            RegCloseKey(hServiceKey);
        }
    }
    
    RegCloseKey(hServicesKey);
    
    // Update count at beginning
    char countStr[64];
    snprintf(countStr, sizeof(countStr), "\n  ],\n  \"vulnerable_count\": %d\n}", vulnCount);
    strcat(json + offset, countStr);
    
    *outJson = json;
    return TRUE;
}

/*
 * Check AlwaysInstallElevated
 */
BOOL Scanner_CheckAlwaysInstallElevated(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    BOOL hkcuEnabled = FALSE;
    BOOL hklmEnabled = FALSE;
    
    // Check HKCU
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                      "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL, 
                             (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            hkcuEnabled = (value == 1);
        }
        RegCloseKey(hKey);
    }
    
    // Check HKLM
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
                             (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            hklmEnabled = (value == 1);
        }
        RegCloseKey(hKey);
    }
    
    BOOL vulnerable = hkcuEnabled && hklmEnabled;
    
    char* json = (char*)malloc(512);
    if (!json) return FALSE;
    
    snprintf(json, 512,
        "{\n"
        "  \"check\": \"always_install_elevated\",\n"
        "  \"hkcu_enabled\": %s,\n"
        "  \"hklm_enabled\": %s,\n"
        "  \"vulnerable\": %s,\n"
        "  \"exploit\": \"%s\"\n"
        "}",
        hkcuEnabled ? "true" : "false",
        hklmEnabled ? "true" : "false",
        vulnerable ? "true" : "false",
        vulnerable ? "msiexec /i malicious.msi" : "N/A");
    
    *outJson = json;
    return TRUE;
}

/*
 * Check for cleartext credentials in common registry locations
 */
BOOL Scanner_CheckRegistryCredentials(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    struct {
        HKEY root;
        const char* rootName;
        const char* path;
        const char* valueName;
        const char* description;
    } regChecks[] = {
        {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultPassword", "Windows Autologon"},
        {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DefaultUserName", "Windows Autologon User"},
        {HKEY_CURRENT_USER, "HKCU", "Software\\SimonTatham\\PuTTY\\Sessions", NULL, "PuTTY Sessions"},
        {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\RealVNC\\WinVNC4", "Password", "VNC Password"},
        {HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\TightVNC\\Server", "Password", "TightVNC Password"},
        {HKEY_CURRENT_USER, "HKCU", "Software\\ORL\\WinVNC3\\Password", NULL, "WinVNC Password"},
        {0, NULL, NULL, NULL, NULL}
    };
    
    char* json = (char*)malloc(8192);
    if (!json) return FALSE;
    
    int offset = snprintf(json, 8192,
        "{\n"
        "  \"check\": \"registry_credentials\",\n"
        "  \"findings\": [\n");
    
    int findCount = 0;
    
    for (int i = 0; regChecks[i].path != NULL; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(regChecks[i].root, regChecks[i].path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char value[512] = {0};
            DWORD size = sizeof(value);
            DWORD type;
            
            BOOL found = FALSE;
            if (regChecks[i].valueName) {
                if (RegQueryValueExA(hKey, regChecks[i].valueName, NULL, &type,
                                     (LPBYTE)value, &size) == ERROR_SUCCESS && size > 1) {
                    found = TRUE;
                }
            } else {
                // Check if key exists (e.g., PuTTY sessions)
                found = TRUE;
                strcpy(value, "[key exists]");
            }
            
            if (found) {
                if (findCount > 0) {
                    offset += snprintf(json + offset, 8192 - offset, ",\n");
                }
                
                // Mask sensitive values
                char masked[64] = "***";
                if (strlen(value) > 0 && strcmp(value, "[key exists]") != 0) {
                    snprintf(masked, sizeof(masked), "[%zu chars]", strlen(value));
                }
                
                offset += snprintf(json + offset, 8192 - offset,
                    "    {\"location\": \"%s\\\\%s\", \"value\": \"%s\", \"desc\": \"%s\"}",
                    regChecks[i].rootName, regChecks[i].path,
                    regChecks[i].valueName ? masked : value,
                    regChecks[i].description);
                findCount++;
            }
            
            RegCloseKey(hKey);
        }
    }
    
    snprintf(json + offset, 8192 - offset, "\n  ],\n  \"findings_count\": %d\n}", findCount);
    
    *outJson = json;
    return TRUE;
}

/*
 * Run all privesc checks and return combined results
 */
BOOL Scanner_PrivescScan(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    char* privJson = NULL;
    char* unquotedJson = NULL;
    char* elevatedJson = NULL;
    char* regCredsJson = NULL;
    
    Scanner_CheckPrivileges(&privJson);
    Scanner_CheckUnquotedPaths(&unquotedJson);
    Scanner_CheckAlwaysInstallElevated(&elevatedJson);
    Scanner_CheckRegistryCredentials(&regCredsJson);
    
    // Combine all results
    size_t totalSize = 1024;
    if (privJson) totalSize += strlen(privJson);
    if (unquotedJson) totalSize += strlen(unquotedJson);
    if (elevatedJson) totalSize += strlen(elevatedJson);
    if (regCredsJson) totalSize += strlen(regCredsJson);
    
    char* json = (char*)malloc(totalSize);
    if (!json) {
        free(privJson);
        free(unquotedJson);
        free(elevatedJson);
        free(regCredsJson);
        return FALSE;
    }
    
    snprintf(json, totalSize,
        "{\n"
        "  \"scan_type\": \"privesc\",\n"
        "  \"privileges\": %s,\n"
        "  \"unquoted_paths\": %s,\n"
        "  \"always_install_elevated\": %s,\n"
        "  \"registry_creds\": %s\n"
        "}",
        privJson ? privJson : "null",
        unquotedJson ? unquotedJson : "null",
        elevatedJson ? elevatedJson : "null",
        regCredsJson ? regCredsJson : "null");
    
    free(privJson);
    free(unquotedJson);
    free(elevatedJson);
    free(regCredsJson);
    
    *outJson = json;
    return TRUE;
}
