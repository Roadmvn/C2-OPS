#ifndef GHOST_SCREENSHOT_H
#define GHOST_SCREENSHOT_H

#include <windows.h>

/**
 * Capture the main screen.
 * Allocates memory for the BMP buffer which must be freed by the caller.
 * 
 * @param buffer Pointer to receive the allocated buffer address
 * @param size Pointer to receive the size of the buffer
 * @return TRUE if successful, FALSE otherwise
 */
BOOL Screenshot_Capture(BYTE** buffer, DWORD* size);

#endif // GHOST_SCREENSHOT_H
