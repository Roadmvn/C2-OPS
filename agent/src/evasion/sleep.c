/*
 * sleep.c - Implémentation du sleep obfuscation
 *
 * Technique inspirée de "Ekko" - chiffre la mémoire heap pendant le sleep
 * pour éviter les détections par scan mémoire.
 *
 * Note: Une implémentation complète nécessiterait du code ROP
 * avec NtContinue/RtlCreateTimer. Ici on fait une version simplifiée.
 */

#include "sleep.h"
#include "../crypto/aes.h"
#include "../utils/memory.h"
#include "syscalls.h"

/* État du module */
static bool g_sleep_initialized = false;

/* Clé temporaire pour le chiffrement pendant le sleep */
static uint8_t g_sleep_key[32];
static uint8_t g_sleep_iv[16];

/* ============================================================================
 * Fonctions internes
 * ============================================================================
 */

/*
 * Génère une clé aléatoire pour ce sleep.
 */
static void generate_sleep_key(void) {
  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);

  /* Simple PRNG basé sur le timestamp */
  srand((unsigned int)(counter.LowPart ^ GetCurrentThreadId()));

  for (int i = 0; i < 32; i++) {
    g_sleep_key[i] = (uint8_t)(rand() & 0xFF);
  }

  for (int i = 0; i < 16; i++) {
    g_sleep_iv[i] = (uint8_t)(rand() & 0xFF);
  }
}

/*
 * Récupère les boundaries de l'image en mémoire.
 */
static bool get_image_boundaries(void **base, size_t *size) {
  HMODULE hmodule = GetModuleHandleA(NULL);
  if (!hmodule) {
    return false;
  }

  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hmodule;
  PIMAGE_NT_HEADERS nt =
      (PIMAGE_NT_HEADERS)((uint8_t *)hmodule + dos->e_lfanew);

  *base = hmodule;
  *size = nt->OptionalHeader.SizeOfImage;

  return true;
}

/* ============================================================================
 * Implémentation des fonctions publiques
 * ============================================================================
 */

int sleep_init(void) {
  if (g_sleep_initialized) {
    return STATUS_SUCCESS;
  }

  /* Génère une clé initiale */
  generate_sleep_key();

  g_sleep_initialized = true;
  return STATUS_SUCCESS;
}

void basic_sleep(DWORD ms) {
  /*
   * Sleep via NtDelayExecution au lieu de Sleep()
   * pour éviter les hooks sur kernel32
   */
  LARGE_INTEGER delay;
  delay.QuadPart = -((LONGLONG)ms * 10000); /* En 100ns, négatif = relatif */

  sys_NtDelayExecution(FALSE, &delay);
}

void obfuscated_sleep(DWORD ms) {
  /*
   * VERSION SIMPLIFIÉE
   *
   * Une vraie implémentation (comme Ekko ou Foliage) utiliserait:
   * 1. RtlCaptureContext pour sauver le contexte
   * 2. Création d'un timer avec callback
   * 3. Le callback fait:
   *    - NtProtectVirtualMemory (RW)
   *    - SystemFunction032 pour chiffrer
   *    - NtProtectVirtualMemory (RX)
   *    - WaitForSingleObject sur le timer
   *    - Déchiffrement
   *    - NtContinue pour restaurer
   *
   * C'est assez complexe et nécessite de l'ASM.
   * Ici on fait une version allégée.
   */

  if (!g_sleep_initialized) {
    basic_sleep(ms);
    return;
  }

  /*
   * Pour l'instant, on fait juste un sleep basique.
   * TODO: Implémenter le chiffrement mémoire complet.
   *
   * Les étapes seraient:
   * 1. Trouver toutes les régions heap de notre process
   * 2. Les chiffrer avec AES
   * 3. Dormir
   * 4. Les déchiffrer
   *
   * Le problème: on peut pas chiffrer le code qui déchiffre...
   * D'où la nécessité d'utiliser des timers système.
   */

  basic_sleep(ms);
}

void sleep_cleanup(void) {
  secure_zero(g_sleep_key, sizeof(g_sleep_key));
  secure_zero(g_sleep_iv, sizeof(g_sleep_iv));
  g_sleep_initialized = false;
}
