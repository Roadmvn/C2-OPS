/*
 * peb.c - Implémentation du PEB Walking
 *
 * Parcourt les structures internes de Windows pour résoudre
 * les fonctions sans passer par les APIs standard.
 */

#include "peb.h"
#include "strings.h"

/* ============================================================================
 * Fonctions internes
 * ============================================================================
 */

/*
 * Calcule le hash DJB2 d'une string ASCII en lowercase.
 */
static uint32_t hash_string_lower(const char *str) {
  uint32_t hash = 5381;
  int c;

  while ((c = *str++)) {
    /* Convertit en lowercase */
    if (c >= 'A' && c <= 'Z') {
      c += 32;
    }
    hash = ((hash << 5) + hash) + c;
  }

  return hash;
}

/*
 * Calcule le hash d'une wide string en lowercase.
 */
static uint32_t hash_wstring_lower(const wchar_t *wstr, size_t len) {
  uint32_t hash = 5381;

  for (size_t i = 0; i < len; i++) {
    wchar_t c = wstr[i];
    /* Convertit en lowercase */
    if (c >= L'A' && c <= L'Z') {
      c += 32;
    }
    hash = ((hash << 5) + hash) + (uint32_t)c;
  }

  return hash;
}

/* ============================================================================
 * Implémentation des fonctions publiques
 * ============================================================================
 */

HMODULE peb_get_module(uint32_t module_hash) {
  /* Récupère le PEB du process courant */
  PPEB peb = NtCurrentPeb();
  if (!peb || !peb->Ldr) {
    return NULL;
  }

  /* Parcourt la liste des modules chargés */
  PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
  PLIST_ENTRY entry = head->Flink;

  while (entry != head) {
    /* Le LDR_DATA_TABLE_ENTRY est offset de 2 pointeurs par rapport au link */
    PLDR_DATA_TABLE_ENTRY module =
        CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    if (module->BaseDllName.Buffer && module->BaseDllName.Length > 0) {
      /* Calcule le hash du nom du module */
      uint32_t name_hash =
          hash_wstring_lower(module->BaseDllName.Buffer,
                             module->BaseDllName.Length / sizeof(wchar_t));

      if (name_hash == module_hash) {
        return (HMODULE)module->DllBase;
      }
    }

    entry = entry->Flink;
  }

  return NULL;
}

FARPROC peb_get_proc(HMODULE module, uint32_t func_hash) {
  if (!module) {
    return NULL;
  }

  /* Parse le PE header pour trouver l'export directory */
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }

  PIMAGE_NT_HEADERS nt_headers =
      (PIMAGE_NT_HEADERS)((uint8_t *)module + dos_header->e_lfanew);
  if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }

  /* Récupère l'export directory */
  DWORD export_rva =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  if (export_rva == 0) {
    return NULL;
  }

  PIMAGE_EXPORT_DIRECTORY exports =
      (PIMAGE_EXPORT_DIRECTORY)((uint8_t *)module + export_rva);

  /* Tableaux d'export */
  DWORD *functions = (DWORD *)((uint8_t *)module + exports->AddressOfFunctions);
  DWORD *names = (DWORD *)((uint8_t *)module + exports->AddressOfNames);
  WORD *ordinals = (WORD *)((uint8_t *)module + exports->AddressOfNameOrdinals);

  /* Parcourt les exports nommés */
  for (DWORD i = 0; i < exports->NumberOfNames; i++) {
    char *func_name = (char *)((uint8_t *)module + names[i]);
    uint32_t name_hash = hash_string_lower(func_name);

    if (name_hash == func_hash) {
      WORD ordinal = ordinals[i];
      DWORD func_rva = functions[ordinal];

      /* Vérifie que c'est pas un forwarded export */
      DWORD export_size =
          nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .Size;
      if (func_rva >= export_rva && func_rva < export_rva + export_size) {
        /* C'est un forward, on l'ignore pour l'instant */
        return NULL;
      }

      return (FARPROC)((uint8_t *)module + func_rva);
    }
  }

  return NULL;
}

FARPROC peb_get_function(uint32_t module_hash, uint32_t func_hash) {
  HMODULE module = peb_get_module(module_hash);
  if (!module) {
    return NULL;
  }

  return peb_get_proc(module, func_hash);
}
