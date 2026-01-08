/*
 * strings.c - Implémentation des fonctions de manipulation de strings
 */

#include "strings.h"
#include "memory.h"

char *str_concat(const char *s1, const char *s2) {
  if (!s1 && !s2)
    return NULL;
  if (!s1)
    return str_dup(s2);
  if (!s2)
    return str_dup(s1);

  size_t len1 = strlen(s1);
  size_t len2 = strlen(s2);

  char *result = (char *)malloc(len1 + len2 + 1);
  if (!result)
    return NULL;

  memcpy(result, s1, len1);
  memcpy(result + len1, s2, len2);
  result[len1 + len2] = '\0';

  return result;
}

char *str_dup(const char *s) {
  if (!s)
    return NULL;

  size_t len = strlen(s);
  char *result = (char *)malloc(len + 1);
  if (!result)
    return NULL;

  memcpy(result, s, len + 1);
  return result;
}

void str_copy(char *dest, size_t dest_size, const char *src) {
  if (!dest || dest_size == 0)
    return;

  if (!src) {
    dest[0] = '\0';
    return;
  }

  size_t i;
  for (i = 0; i < dest_size - 1 && src[i] != '\0'; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
}

int str_icmp(const char *s1, const char *s2) {
  if (!s1 && !s2)
    return 0;
  if (!s1)
    return -1;
  if (!s2)
    return 1;

  while (*s1 && *s2) {
    char c1 = *s1;
    char c2 = *s2;

    /* Convertit en lowercase */
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 32;
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 32;

    if (c1 != c2) {
      return c1 - c2;
    }

    s1++;
    s2++;
  }

  return *s1 - *s2;
}

bool str_starts_with(const char *str, const char *prefix) {
  if (!str || !prefix)
    return false;

  size_t prefix_len = strlen(prefix);
  if (strlen(str) < prefix_len)
    return false;

  return strncmp(str, prefix, prefix_len) == 0;
}

bool str_ends_with(const char *str, const char *suffix) {
  if (!str || !suffix)
    return false;

  size_t str_len = strlen(str);
  size_t suffix_len = strlen(suffix);

  if (str_len < suffix_len)
    return false;

  return strcmp(str + str_len - suffix_len, suffix) == 0;
}

int str_to_int(const char *str) {
  if (!str)
    return 0;

  int result = 0;
  int sign = 1;

  /* Skip whitespace */
  while (*str == ' ' || *str == '\t')
    str++;

  /* Handle sign */
  if (*str == '-') {
    sign = -1;
    str++;
  } else if (*str == '+') {
    str++;
  }

  /* Parse digits */
  while (*str >= '0' && *str <= '9') {
    result = result * 10 + (*str - '0');
    str++;
  }

  return result * sign;
}

void int_to_str(int value, char *buffer, size_t buffer_size) {
  if (!buffer || buffer_size < 2)
    return;

  snprintf(buffer, buffer_size, "%d", value);
}

char *wstr_to_str(const wchar_t *wstr) {
  if (!wstr)
    return NULL;

  /* Calcule la taille nécessaire */
  int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  if (size <= 0)
    return NULL;

  char *result = (char *)malloc(size);
  if (!result)
    return NULL;

  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result, size, NULL, NULL);
  return result;
}

wchar_t *str_to_wstr(const char *str) {
  if (!str)
    return NULL;

  /* Calcule la taille nécessaire */
  int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  if (size <= 0)
    return NULL;

  wchar_t *result = (wchar_t *)malloc(size * sizeof(wchar_t));
  if (!result)
    return NULL;

  MultiByteToWideChar(CP_UTF8, 0, str, -1, result, size);
  return result;
}

uint32_t str_hash(const char *str) {
  if (!str)
    return 0;

  uint32_t hash = 5381;
  int c;

  while ((c = *str++)) {
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }

  return hash;
}

uint32_t wstr_hash(const wchar_t *wstr) {
  if (!wstr)
    return 0;

  uint32_t hash = 5381;
  wchar_t c;

  while ((c = *wstr++)) {
    hash = ((hash << 5) + hash) + c;
  }

  return hash;
}
