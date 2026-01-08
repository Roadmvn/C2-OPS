/*
 * memory.c - Implémentation mémoire sécurisée
 */

#include "memory.h"

/* Variable volatile pour empêcher l'optimisation du zeroing */
static volatile void *secure_zero_ptr;

void *secure_alloc(size_t size) {
  if (size == 0) {
    return NULL;
  }

  void *ptr = malloc(size);
  if (ptr) {
    memset(ptr, 0, size);
  }

  return ptr;
}

void *secure_realloc(void *ptr, size_t old_size, size_t new_size) {
  if (new_size == 0) {
    secure_free(ptr, old_size);
    return NULL;
  }

  if (!ptr) {
    return secure_alloc(new_size);
  }

  void *new_ptr = malloc(new_size);
  if (!new_ptr) {
    return NULL;
  }

  /* Copie les anciennes données */
  size_t copy_size = (old_size < new_size) ? old_size : new_size;
  memcpy(new_ptr, ptr, copy_size);

  /* Zero le reste si on agrandit */
  if (new_size > old_size) {
    memset((uint8_t *)new_ptr + old_size, 0, new_size - old_size);
  }

  /* Zero et libère l'ancien buffer */
  secure_free(ptr, old_size);

  return new_ptr;
}

void secure_free(void *ptr, size_t size) {
  if (!ptr) {
    return;
  }

  /* Zero la mémoire avant de libérer */
  secure_zero(ptr, size);

  free(ptr);
}

void secure_zero(void *ptr, size_t size) {
  if (!ptr || size == 0) {
    return;
  }

  /*
   * On utilise SecureZeroMemory de Windows si dispo,
   * sinon on fait un memset avec un trick pour empêcher
   * l'optimisation.
   */
#ifdef _WIN32
  SecureZeroMemory(ptr, size);
#else
  /* Fallback pour les autres plateformes (compilation croisée) */
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (size--) {
    *p++ = 0;
  }
  /* Force le compilateur à garder l'opération */
  secure_zero_ptr = ptr;
#endif
}

int secure_memcpy(void *dest, size_t dest_size, const void *src, size_t count) {
  if (!dest || !src) {
    return STATUS_FAILURE;
  }

  if (count > dest_size) {
    return STATUS_FAILURE; /* Overflow protection */
  }

  memcpy(dest, src, count);
  return STATUS_SUCCESS;
}
