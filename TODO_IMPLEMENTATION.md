# Ghost C2 - État de l'implémentation

> Dernière mise à jour: 28 Jan 2026 - FINAL

## État actuel

| Module | Agent (C) | Server (Go) | Status |
|--------|-----------|-------------|--------|
| Core | demon.c, config.c, auth.c | main.go | Done |
| Crypto | aes.c, xor.c, base64.c | aes.go | Done |
| Network | transport.c, profile.c | http.go, manager.go | Done |
| Sessions | - | agent.go, manager.go | Done |
| Tasks | dispatcher.c + handlers | queue.go | Done |
| Evasion | antidebug.c, sandbox.c, sleep.c, syscalls.c, injection.c | - | Done |
| API | - | router.go | Done |
| CLI | - | console.go | Done |
| Surveillance | screenshot.c, keylogger.c, clipboard.c, webcam.c, microphone.c | handlers/*.go | Done |
| Remote Desktop | desktop.c | remote.go | Done |
| Credentials | browser.c, lsass.c | credentials.go | Partial |
| Exfiltration | exfil.c | - | Partial |
| Network Tools | socks5.c, portfwd.c | - | Done |
| Scanner | scanner.c | - | Partial |
| Self-Destruct | destruct.c | - | Done |

---

## Incomplet - À corriger

### Browser Credentials (browser.c)

Fait:
- Détection du chemin Chrome Login Data
- Structure de déchiffrement DPAPI
- Parsing JSON basique
- [x] Déchiffrement BCrypt AES-GCM pour Chrome v80+
- [x] Parsing SQLite heuristique
- [x] Détection profils Firefox (profiles.ini)
- [x] Parsing logins.json Firefox
- [x] Fonction combinée Browser_GetAllCredentials()

À faire:
- [ ] Intégration librairie NSS pour Firefox (retourne actuellement les valeurs chiffrées)

### File Exfiltration (exfil.c)

Done:
- Extension-based search
- Keyword-based search
- Recursive directory scanning
- Single file read
- [x] Chunked upload for large files (1MB chunks)
- [x] File info + state tracking

TODO:
- [ ] Compression before upload (optional)

### Authentication (auth.c)

Fait:
- Build key structure
- Agent ID generation (hardware-based)
- HMAC-SHA256 challenge-response
- [x] Kill switch (Auth_ActivateKillSwitch, Auth_IsKilled)
- [x] Heartbeat system (Auth_GenerateHeartbeat, Auth_ValidateServerResponse)
- [x] Server response validation avec blacklist check

À faire:
- [ ] Server-side validation endpoint (Go)

### Vulnerability Scanner (scanner.c)

Done:
- Port scanning (TCP connect)
- Service fingerprinting
- Common ports detection
- Host up check
- [x] SeImpersonatePrivilege check
- [x] SeDebugPrivilege, SeBackup, SeRestore checks
- [x] Unquoted service paths detection
- [x] AlwaysInstallElevated check
- [x] Cleartext credentials in registry (Autologon, VNC, PuTTY)
- [x] Combined privesc scan function

Fait:
- [x] Weak file permissions check (Scanner_CheckWeakPermissions)
- [x] Writable PATH directories check (Scanner_CheckWritablePath)

---

## Implémenté récemment

### Advanced Injection (injection.c)

- [x] Process Hollowing (Injection_ProcessHollowing)
- [x] APC Injection (Injection_APC)
- [x] Early Bird APC (Injection_EarlyBirdAPC)
- [x] Process finder + injectable list

### Sleep Obfuscation (sleep.c)

- [x] Heap encryption during sleep (RC4 via SystemFunction032)
- [x] XOR fallback encryption
- [x] Sleep with jitter (sleep_with_jitter)
- [x] Region enumeration + protection handling

---

## Implémenté - Persistence avancée (persist.c)

- [x] COM Hijacking (persist_com_hijack_add/remove)
- [x] WMI Event Subscription (persist_wmi_add/remove)
- [x] AppInit_DLLs (persist_appinit_add/remove)
- [x] Image File Execution Options (persist_ifeo_add/remove)
- [x] Scheduled Task via COM API (persist_schtask_com_add/remove)

## Implémenté - Injection avancée (injection.c)

- [x] Reflective DLL Loading (Injection_ReflectiveLoadDLL)
- [x] Export resolution for reflective DLLs
- [x] Remote reflective injection
- [x] Module Stomping local/distant (Injection_ModuleStomp)
- [x] Stack Spoofing (Injection_CallWithSpoofedStack)
- [x] Thread Execution Hijacking (Injection_ThreadHijack)
- [x] Thread Hijacking avec restauration contexte

## Implémenté - Callback-based Execution

- [x] ThreadPool callback (Injection_ThreadPoolCallback)
- [x] Timer APC callback (Injection_TimerCallback)
- [x] EnumWindows callback (Injection_EnumWindowsCallback)
- [x] CertEnumSystemStore callback (Injection_CertEnumCallback)
- [x] CopyFile2 progress callback (Injection_CopyFileCallback)

## Implémenté - Fiber Injection

- [x] Fiber local (Injection_FiberLocal)
- [x] Fiber safe avec wrapper (Injection_FiberSafe)

## Implémenté - Syscalls directs (syscalls.c)

- [x] Résolution dynamique des SSN (Halo's Gate)
- [x] Détection des hooks EDR
- [x] Gadget syscall;ret finder
- [x] direct_syscalls_init() / direct_syscalls_dump()

## Implémenté - Évasion EDR (edr_evasion.c)

- [x] ETW Patching (Evasion_PatchETW, Evasion_DisableETW)
- [x] AMSI Bypass (Evasion_PatchAMSI, Evasion_AmsiInitFailedBypass)
- [x] Unhooking ntdll (Evasion_UnhookNtdll, Evasion_UnhookFunction)
- [x] Détection de hooks (Evasion_IsFunctionHooked, Evasion_ListHookedFunctions)
- [x] CLR ETW bypass (Evasion_DisableCLRETW)
- [x] Full bypass combiné (Evasion_FullBypass)

## Implémenté - Obfuscation (obfuscation.c)

- [x] API hashing (DJB2, SDBM, FNV-1a, Custom)
- [x] API resolution par hash avec cache
- [x] String encryption (XOR, rolling XOR, multi-key)
- [x] Stack strings (construction dynamique)
- [x] Hashes pré-calculés pour modules/fonctions
- [x] Control flow obfuscation (opaque predicates)
- [x] Junk code generation

## Implémenté - Code Polymorphique (polymorph.c)

- [x] XOR encoding avec décodeur auto-généré
- [x] Multi-byte XOR encoding (clé jusqu'à 16 bytes)
- [x] Insertion de junk code aléatoire
- [x] Substitution d'instructions équivalentes
- [x] Génération polymorphique complète
- [x] Support x86 et x64

## Complet !

L'agent C2-OPS dispose maintenant de toutes les fonctionnalités essentielles:
- Injection (9 techniques)
- Persistence (7 méthodes)
- Évasion EDR (ETW, AMSI, Unhook)
- Syscalls directs
- Obfuscation (API hash, string encryption)
- Code polymorphique

---

## Notes techniques

### Chrome v80+ Password Decryption

```c
// 1. Read Local State -> extract encrypted_key (base64)
// 2. Base64 decode -> skip "DPAPI" prefix (5 bytes)
// 3. CryptUnprotectData to get master key

// 4. For each row in Login Data SQLite:
//    - password_value starts with "v10" or "v11"
//    - IV = bytes[3:15]
//    - ciphertext = bytes[15:-16]  
//    - tag = bytes[-16:]
//    - Decrypt with BCryptDecrypt (AES-GCM)
```

### Chunked Upload

```c
#define CHUNK_SIZE (1024 * 1024)  // 1MB

// Split file into chunks
// Send each chunk with: file_id, chunk_index, total_chunks, data
// Server reassembles
```

### Privilege Escalation Checks

```c
// SeImpersonatePrivilege
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
// Check for SeImpersonatePrivilege in token

// Unquoted service paths
// Query: HKLM\SYSTEM\CurrentControlSet\Services\*
// Check ImagePath for spaces without quotes

// AlwaysInstallElevated
// HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
// HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
// Both must have AlwaysInstallElevated = 1
```

---

## Structure des fichiers

```
agent/src/
├── core/
│   ├── auth.c          <- needs server validation
│   ├── config.c
│   └── demon.c
├── credentials/
│   ├── browser.c       <- needs SQLite + AES-GCM
│   └── lsass.c
├── exfil/
│   └── exfil.c         <- needs chunked upload
├── recon/
│   └── scanner.c       <- needs privesc checks
└── ...
```
