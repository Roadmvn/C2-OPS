/*
 * desktop.c - Remote Desktop capture et contrôle
 *
 * Capture d'écran via GDI + compression JPEG via GDI+
 * Injection d'inputs via SendInput()
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wingdi.h>
#include <stdio.h>
#include <stdlib.h>

// Pour COM/IStream (nécessaire pour GDI+)
#include <objbase.h>
#include <objidl.h>

// Type manquant pour GDI+
#ifndef PROPID
typedef ULONG PROPID;
#endif

// GDI+ headers (pour compression JPEG)
#include <gdiplus.h>

// Pour SendInput
#pragma comment(lib, "user32.lib")

/* GDI+ state */
static ULONG_PTR g_gdiplusToken = 0;
static BOOL g_gdiplusInit = FALSE;

/* Initialise GDI+ */
static BOOL InitGdiPlus(void) {
    if (g_gdiplusInit) return TRUE;
    
    GdiplusStartupInput input;
    memset(&input, 0, sizeof(input));
    input.GdiplusVersion = 1;
    
    if (GdiplusStartup(&g_gdiplusToken, &input, NULL) == Ok) {
        g_gdiplusInit = TRUE;
        return TRUE;
    }
    return FALSE;
}

/* Cleanup GDI+ */
static void CleanupGdiPlus(void) {
    if (g_gdiplusInit) {
        GdiplusShutdown(g_gdiplusToken);
        g_gdiplusInit = FALSE;
    }
}

/* Trouve l'encoder CLSID pour un format donné (JPEG, PNG, etc.) */
static BOOL GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    
    GdipGetImageEncodersSize(&num, &size);
    if (size == 0) return FALSE;
    
    ImageCodecInfo* pCodecs = (ImageCodecInfo*)malloc(size);
    if (!pCodecs) return FALSE;
    
    GdipGetImageEncoders(num, size, pCodecs);
    
    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pCodecs[i].MimeType, format) == 0) {
            *pClsid = pCodecs[i].Clsid;
            free(pCodecs);
            return TRUE;
        }
    }
    
    free(pCodecs);
    return FALSE;
}

/* Screen capture */

/*
 * Capture l'écran entier et retourne les données JPEG.
 * quality: 1-100 (qualité JPEG)
 * L'appelant doit libérer outData avec free().
 */
BOOL Desktop_CaptureScreen(BYTE** outData, DWORD* outSize, int quality) {
    if (!outData || !outSize) return FALSE;
    *outData = NULL;
    *outSize = 0;
    
    // Initialise GDI+ si nécessaire
    if (!InitGdiPlus()) return FALSE;
    
    // Récupère les dimensions de l'écran
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Crée les DC
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    // Crée un bitmap compatible
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    // Copie l'écran dans le bitmap
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    
    // Restaure et libère les DC
    SelectObject(hdcMem, hOldBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    // Convertit en GDI+ Bitmap pour compression JPEG
    GpBitmap* gpBitmap = NULL;
    if (GdipCreateBitmapFromHBITMAP(hBitmap, NULL, &gpBitmap) != Ok) {
        DeleteObject(hBitmap);
        return FALSE;
    }
    
    DeleteObject(hBitmap);
    
    // Trouve l'encoder JPEG
    CLSID jpegClsid;
    if (!GetEncoderClsid(L"image/jpeg", &jpegClsid)) {
        GdipDisposeImage(gpBitmap);
        return FALSE;
    }
    
    // Configure la qualité JPEG
    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = EncoderQuality;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;
    ULONG qualityValue = (quality > 0 && quality <= 100) ? quality : 50;
    encoderParams.Parameter[0].Value = &qualityValue;
    
    // Crée un stream en mémoire pour stocker le JPEG
    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) {
        GdipDisposeImage(gpBitmap);
        return FALSE;
    }
    
    // Sauvegarde dans le stream
    if (GdipSaveImageToStream(gpBitmap, pStream, &jpegClsid, &encoderParams) != Ok) {
        pStream->lpVtbl->Release(pStream);
        GdipDisposeImage(gpBitmap);
        return FALSE;
    }
    
    GdipDisposeImage(gpBitmap);
    
    // Récupère les données du stream
    HGLOBAL hMem = NULL;
    if (GetHGlobalFromStream(pStream, &hMem) != S_OK) {
        pStream->lpVtbl->Release(pStream);
        return FALSE;
    }
    
    SIZE_T dataSize = GlobalSize(hMem);
    BYTE* pData = (BYTE*)GlobalLock(hMem);
    
    if (pData && dataSize > 0) {
        *outData = (BYTE*)malloc(dataSize);
        if (*outData) {
            memcpy(*outData, pData, dataSize);
            *outSize = (DWORD)dataSize;
        }
    }
    
    GlobalUnlock(hMem);
    pStream->lpVtbl->Release(pStream);
    
    return (*outData != NULL);
}

/* Input injection */

/*
 * Injecte un événement souris.
 * x, y: coordonnées absolues (0-65535 normalisées)
 * flags: combinaison de:
 *   1 = MOVE
 *   2 = LEFT_DOWN
 *   4 = LEFT_UP
 *   8 = RIGHT_DOWN
 *   16 = RIGHT_UP
 */
BOOL Desktop_InjectMouse(int x, int y, DWORD flags) {
    INPUT input = {0};
    input.type = INPUT_MOUSE;
    
    // Convertit en coordonnées absolues (0-65535)
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    input.mi.dx = (x * 65535) / screenWidth;
    input.mi.dy = (y * 65535) / screenHeight;
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE;
    
    // Ajoute les flags
    if (flags & 1) input.mi.dwFlags |= MOUSEEVENTF_MOVE;
    if (flags & 2) input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
    if (flags & 4) input.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
    if (flags & 8) input.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
    if (flags & 16) input.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
    
    return SendInput(1, &input, sizeof(INPUT)) == 1;
}

/*
 * Injecte un événement clavier.
 * vkCode: code de touche virtuelle (VK_*)
 * keyUp: TRUE pour key up, FALSE pour key down
 */
BOOL Desktop_InjectKey(WORD vkCode, BOOL keyUp) {
    INPUT input = {0};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vkCode;
    
    if (keyUp) {
        input.ki.dwFlags = KEYEVENTF_KEYUP;
    }
    
    return SendInput(1, &input, sizeof(INPUT)) == 1;
}
