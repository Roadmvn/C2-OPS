/*
 * injection.h - Prototypes pour les techniques d'injection
 */

#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

/* Process Hollowing */
BOOL Injection_ProcessHollowing(const char* targetPath, BYTE* payload, DWORD payloadSize);

/* APC Injection */
BOOL Injection_APC(DWORD targetPid, BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_EarlyBirdAPC(const char* targetPath, BYTE* shellcode, DWORD shellcodeSize);

/* Utilitaires */
DWORD Injection_FindProcessByName(const char* processName);
BOOL Injection_ListInjectableProcesses(char** outJson);

#endif /* INJECTION_H */
