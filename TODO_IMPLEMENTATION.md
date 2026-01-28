# Ghost C2 - Implementation Status

> Last updated: Jan 2026

## Current State

| Module | Agent (C) | Server (Go) | Status |
|--------|-----------|-------------|--------|
| Core | demon.c, config.c, auth.c | main.go | Done |
| Crypto | aes.c, xor.c, base64.c | aes.go | Done |
| Network | transport.c, profile.c | http.go, manager.go | Done |
| Sessions | - | agent.go, manager.go | Done |
| Tasks | dispatcher.c + handlers | queue.go | Done |
| Evasion | antidebug.c, sandbox.c, sleep.c, syscalls.c | - | Done |
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

## Incomplete - To Fix

### Browser Credentials (browser.c)

Done:
- Chrome Login Data path detection
- DPAPI decryption structure
- Basic JSON parsing
- [x] BCrypt AES-GCM decryption for Chrome v80+ passwords
- [x] Raw SQLite parsing (heuristic blob detection)
- [x] Firefox profile detection (profiles.ini)
- [x] Firefox logins.json parsing
- [x] Browser_GetAllCredentials() combined function

TODO:
- [ ] NSS library integration for Firefox decryption (currently returns encrypted values)

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

Done:
- Build key structure
- Agent ID generation (hardware-based)
- HMAC-SHA256 challenge-response

TODO:
- [ ] Server-side validation endpoint
- [ ] Kill switch implementation (revoke agent by ID)
- [ ] Agent blacklist/whitelist

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

TODO:
- [ ] Weak file permissions check (writable service binaries)

---

## Not Started

### Advanced Injection

- [ ] Process Hollowing
- [ ] APC Injection
- [ ] Reflective DLL loading
- [ ] Module stomping

### Advanced Persistence

- [ ] COM Hijacking
- [ ] WMI Event Subscription
- [ ] Scheduled Task via COM API
- [ ] AppInit_DLLs
- [ ] Image File Execution Options

### Sleep Obfuscation (full)

Current: basic NtDelayExecution

TODO:
- [ ] Heap encryption during sleep
- [ ] ROP chain with NtContinue
- [ ] Timer-based callback
- [ ] Stack spoofing

---

## Technical Notes

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

## File Structure

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
