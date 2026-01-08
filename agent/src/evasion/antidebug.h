/*
 * antidebug.h - Techniques de détection de debugger
 *
 * Plusieurs techniques pour détecter si on est analysé.
 * Si un debugger est détecté, on peut soit exit, soit fake behavior.
 */

#ifndef ANTIDEBUG_H
#define ANTIDEBUG_H

#include "../../include/common.h"

/*
 * Vérifie si un debugger est attaché.
 * Combine plusieurs techniques pour plus de fiabilité.
 */
bool is_debugger_present(void);

/*
 * Check via le PEB (BeingDebugged flag).
 */
bool check_peb_being_debugged(void);

/*
 * Check via NtQueryInformationProcess (ProcessDebugPort).
 */
bool check_debug_port(void);

/*
 * Check via NtQueryInformationProcess (ProcessDebugFlags).
 */
bool check_debug_flags(void);

/*
 * Check via NtQueryInformationProcess (ProcessDebugObjectHandle).
 */
bool check_debug_object_handle(void);

/*
 * Check par timing - les debuggers ralentissent l'exécution.
 */
bool check_timing_attack(void);

/*
 * Check les noms de process suspects (ollydbg, x64dbg, etc).
 */
bool check_analysis_processes(void);

/*
 * Check les noms de fenêtres suspects.
 */
bool check_analysis_windows(void);

#endif /* ANTIDEBUG_H */
