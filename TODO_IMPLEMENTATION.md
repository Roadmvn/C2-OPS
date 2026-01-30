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

## 🎯 Roadmap Prioritaire (Analyse Consolidée - 30 Jan 2026)

| Priorité | Module | Objectif | Status |
|----------|--------|----------|--------|
| **P0** | `privesc.c` | Exploiter Unquoted Service Path, AlwaysInstallElevated | ✅ **Done** |
| **P1** | `lateral.c` | SCM/PsExec, WMI, DCOM | 🔴 TODO |
| **P2** | SMB Named Pipes | Transport P2P inter-agents | 🔴 TODO |
| **P3** | DNS Tunneling | Transport TXT records | 🔴 TODO |
| **P4** | Cloud Exfil | OneDrive/Google Drive API | 🔴 TODO |
| **P5** | Firefox NSS, Compression | Finalisation modules existants | 🔴 TODO |

### ✅ P0 Implémenté (30 Jan 2026)
- `agent/src/privesc/privesc.h` - Headers avec 6 vulnérabilités types
- `agent/src/privesc/privesc.c` - Implémentation complète (520+ lignes)
  - `PrivEsc_ScanAll()` - Scan 5 types de vulns
  - `PrivEsc_ExploitUnquotedPath()` - Exploit service path
  - `PrivEsc_ExploitAlwaysInstallElevated()` - MSI abuse
  - `PrivEsc_GetSystem()` - Token stealing (winlogon/lsass)
  - `PrivEsc_HasSeImpersonate()` - Check privilèges
  - `PrivEsc_PotatoGetSystem()` - Named pipe impersonation

### Prochaine Action : Créer `agent/src/lateral/`
1. `lateral.h` - Headers pour mouvement latéral
2. `lateral.c` - SCM/PsExec, WMI, DCOM
3. Intégrer avec token volé de privesc

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

## 🎯 Roadmap - Priorités

### P0 - Quick Wins (1-2 jours chacun)

| Feature | Status | Fichier | Notes |
|---------|--------|---------|-------|
| Server-side auth endpoint | [ ] | `server/internal/auth/` | Endpoint Go pour validation agent |
| Compression zlib | [ ] | `agent/src/exfil/exfil.c` | ~50 lignes de code |
| NSS Firefox integration | [ ] | `agent/src/credentials/browser.c` | Déchiffrement passwords Firefox |

### P1 - Features Critiques (3-5 jours chacun)

| Feature | Status | Impact | Complexité |
|---------|--------|--------|------------|
| DNS Exfiltration | [ ] | C2 over DNS, bypass firewalls restrictifs | Moyenne |
| BOF Loader | [ ] | Charger des Beacon Object Files dynamiquement | Moyenne |
| LDAP Recon | [ ] | AD enumeration sans PowerShell | Basse |
| Named Pipes C2 | [ ] | C2 over SMB, mouvement latéral interne | Moyenne |

### P2 - Différenciation (1-2 semaines)

| Feature | Status | Impact | Complexité |
|---------|--------|--------|------------|
| In-memory .NET execution | [ ] | Execute-Assembly sans spawn CLR | Haute |
| SMB Lateral Movement | [ ] | PSExec/WMIExec style | Moyenne |
| Steganography Exfil | [ ] | Bypass DLP, ultra-furtif | Moyenne |
| Cloud Exfil | [ ] | OneDrive/Dropbox/GDrive | Haute |

---

## Prochaines étapes - Exfiltration avancée

### DNS Exfiltration
- [ ] Encodage des données en sous-domaines DNS (base32/base64)
- [ ] Requêtes TXT/CNAME pour récupérer les données
- [ ] Très discret - passe souvent inaperçu par les EDR
- [ ] Lent mais fiable même dans les réseaux restrictifs
- [ ] Implémenter: `agent/src/exfil/dns_exfil.c`

### Steganography
- [ ] Cacher les données dans des images PNG/JPEG
- [ ] LSB (Least Significant Bit) encoding
- [ ] Les fichiers ressemblent à des images normales
- [ ] Bypass DLP (Data Loss Prevention)
- [ ] Implémenter: `agent/src/exfil/stego.c`

### Cloud Exfiltration
- [ ] Upload vers services légitimes (OneDrive, Dropbox, Google Drive)
- [ ] Utilise le trafic HTTPS normal
- [ ] Difficile à bloquer sans casser la productivité
- [ ] API ou WebDAV
- [ ] Implémenter: `agent/src/exfil/cloud.c`

### Compression (optimisation)
- [ ] Compression zlib/lz4 avant upload
- [ ] Réduit la bande passante
- [ ] Accélère les transferts
- [ ] Moins de données = moins de temps d'exposition

---

## Prochaines étapes - C2 Multi-Protocol

### Named Pipes (SMB)
- [ ] C2 over SMB named pipes
- [ ] Communication processus-to-processus locale
- [ ] Pivot interne sans réseau
- [ ] Implémenter: `agent/src/network/pipe.c`

### BOF Loader
- [ ] Parser le format COFF (.o)
- [ ] Résoudre les symboles dynamiquement
- [ ] Exécuter en mémoire sans créer de fichier
- [ ] Compatible avec les BOFs Cobalt Strike
- [ ] Implémenter: `agent/src/core/bof_loader.c`

---

## Prochaines étapes - Post-Exploitation

### LDAP Recon (AD Enumeration)
- [ ] Énumérer utilisateurs, groupes, OUs
- [ ] Trouver les Domain Admins
- [ ] Lister les GPOs
- [ ] Détecter les chemins de privesc (ACLs)
- [ ] Implémenter: `agent/src/recon/ldap.c`

### Kerberos Attacks
- [ ] Kerberoasting (SPN enumeration + TGS request)
- [ ] AS-REP Roasting
- [ ] Silver Ticket (si on a le hash)
- [ ] Implémenter: `agent/src/credentials/kerberos.c`

### In-Memory .NET Execution
- [ ] Charger le CLR dynamiquement
- [ ] Exécuter des assemblies .NET en mémoire
- [ ] Bypass AMSI inline
- [ ] Implémenter: `agent/src/core/execute_assembly.c`

---

## 🚀 Différenciateurs vs Concurrence

| Feature | Cobalt Strike | Havoc | Sliver | Ghost C2 |
|---------|--------------|-------|--------|----------|
| Syscalls directs | Opt-in | ✅ | ❌ | ✅ |
| Sleep obfuscation | ✅ | ✅ | ❌ | ✅ |
| BOF Loader | ✅ | ✅ | ❌ | 🔲 TODO |
| DNS C2 | ✅ | ❌ | ✅ | 🔲 TODO |
| Polymorphisme | ❌ | ❌ | ❌ | ✅ |
| Code source | ❌ Closed | ✅ | ✅ | ✅ |

---

## 📊 Métriques de progression

- **Agent (C)**: ~90% complet
- **Server (Go)**: ~85% complet
- **Web UI (React)**: ~60% complet - Besoin d'amélioration UX
- **Documentation**: ~70% complet

---

## Fonctionnalités complètes

L'agent C2-OPS dispose de toutes les fonctionnalités essentielles:
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
