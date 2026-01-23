# Guide des Techniques MITRE ATT&CK

Ce document explique les techniques offensives utilisées dans Ghost C2, mappées sur le framework MITRE ATT&CK.

---

## Table des matières
1. [Introduction au MITRE ATT&CK](#introduction)
2. [Dropper](#dropper)
3. [Loader](#loader)
4. [Packer / Crypter](#packer--crypter)
5. [Stager vs Stageless](#stager-vs-stageless)
6. [C2 (Command & Control)](#c2-command--control)
7. [Techniques d'évasion](#techniques-dévasion)
8. [Persistence](#persistence)
9. [Credential Access](#credential-access)
10. [Lateral Movement](#lateral-movement)

---

## Introduction

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) est une base de connaissances des tactiques et techniques utilisées par les attaquants. Elle sert de référence pour :
- Comprendre les méthodes d'attaque
- Développer des défenses
- Tester la sécurité (Red Team)

```
Tactiques (OBJECTIF) → Techniques (COMMENT) → Procédures (IMPLÉMENTATION)
```

---

## Dropper

### Qu'est-ce qu'un Dropper ?

Un **dropper** est un programme dont le seul but est de **déposer** (drop) un autre payload sur le système cible. Il ne contient généralement pas de fonctionnalités malveillantes en lui-même.

### Fonctionnement

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Utilisateur     │───▶│   Dropper    │───▶│  Payload final  │
│ exécute .exe    │    │  (déchiffre) │    │  (ghost.exe)    │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              │
                              ▼
                       Écrit sur disque
                       puis exécute
```

### Types de Droppers

| Type | Description | Exemple |
|------|-------------|---------|
| **Disk Dropper** | Écrit le payload sur le disque avant exécution | CreateFile → WriteFile → CreateProcess |
| **Memory Dropper** | Injecte directement en mémoire (fileless) | VirtualAlloc → memcpy → CreateThread |
| **Self-extracting** | Archive auto-extractible (.sfx) | 7z SFX, WinRAR SFX |

### MITRE ATT&CK
- **T1204** - User Execution
- **T1105** - Ingress Tool Transfer

### Exemple simplifié (pseudo-code)

```c
// Dropper basique
void main() {
    // 1. Payload chiffré embarqué
    BYTE encrypted_payload[] = { 0x4D, 0x5A, ... };
    
    // 2. Déchiffrement XOR
    for (int i = 0; i < sizeof(encrypted_payload); i++) {
        encrypted_payload[i] ^= KEY;
    }
    
    // 3. Écriture sur disque
    HANDLE hFile = CreateFile("C:\\Windows\\Temp\\svchost.exe", ...);
    WriteFile(hFile, encrypted_payload, size, ...);
    CloseHandle(hFile);
    
    // 4. Exécution
    ShellExecute(NULL, "open", "C:\\Windows\\Temp\\svchost.exe", ...);
}
```

---

## Loader

### Qu'est-ce qu'un Loader ?

Un **loader** est similaire à un dropper, mais au lieu d'écrire sur disque, il **charge directement le payload en mémoire** et l'exécute. C'est une technique "fileless".

### Différence Dropper vs Loader

| Aspect | Dropper | Loader |
|--------|---------|--------|
| Écriture disque | Oui | Non |
| Détection AV | Plus facile | Plus difficile |
| Forensics | Laisse des traces | Fileless |
| Complexité | Simple | Plus complexe |

### Technique de Reflective Loading

```
┌─────────────────┐
│    Loader       │
│                 │
│ 1. VirtualAlloc │──────▶ Allocation mémoire RWX
│ 2. memcpy       │──────▶ Copie du PE
│ 3. Fix imports  │──────▶ Résolution des imports
│ 4. Fix relocs   │──────▶ Correction des relocations
│ 5. Execute      │──────▶ Appel du point d'entrée
│                 │
└─────────────────┘
```

### MITRE ATT&CK
- **T1620** - Reflective Code Loading
- **T1055** - Process Injection

---

## Packer / Crypter

### Définitions

- **Packer** : Compresse et/ou chiffre un exécutable pour réduire sa taille et/ou évader les signatures AV
- **Crypter** : Spécifiquement conçu pour chiffrer le payload et le rendre FUD (Fully Undetectable)

### Fonctionnement d'un Packer

```
┌─────────────────┐           ┌─────────────────┐
│  Original.exe   │  PACKING  │   Packed.exe    │
│                 │──────────▶│                 │
│ Code lisible    │           │ ┌─────────────┐ │
│ Imports visibles│           │ │ Stub (code) │ │
│ Strings clairs  │           │ ├─────────────┤ │
│                 │           │ │ Payload     │ │
│                 │           │ │ (chiffré)   │ │
└─────────────────┘           │ └─────────────┘ │
                              └─────────────────┘

À l'exécution:
1. Le stub se lance
2. Déchiffre le payload en mémoire
3. Exécute le code original
```

### Packers connus

| Nom | Type | Usage |
|-----|------|-------|
| **UPX** | Compression | Légitime, détecté |
| **Themida** | Protection commerciale | Anti-debug, anti-VM |
| **VMProtect** | Virtualisation | Transforme le code en bytecode VM |
| **Custom** | Fait maison | Meilleur pour évasion |

### Techniques Anti-Unpacking

1. **Anti-debugging** : Détecte les debuggers
2. **Code obfuscation** : Rend le code difficile à lire
3. **Import hiding** : Cache les imports Windows
4. **String encryption** : Chiffre toutes les strings
5. **Junk code** : Ajoute du code inutile

### MITRE ATT&CK
- **T1027** - Obfuscated Files or Information
- **T1027.002** - Software Packing

---

## Stager vs Stageless

### Stager (Multi-stage)

Le payload initial est **petit** et télécharge le payload complet depuis le C2.

```
Phase 1: Stager (petit, ~5KB)
┌────────────────────────────────────────────────────────────┐
│ 1. Connexion au C2                                         │
│ 2. Téléchargement du stage 2                              │
│ 3. Exécution en mémoire                                    │
└────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 2: Full Payload (~100KB+)
┌────────────────────────────────────────────────────────────┐
│ Keylogger, Screenshot, Shell, etc.                         │
└────────────────────────────────────────────────────────────┘
```

**Avantages** :
- Payload initial plus petit (moins suspect)
- Payload principal jamais sur disque
- Mise à jour facile du payload

**Inconvénients** :
- Besoin de connectivité réseau
- Trafic réseau détectable

### Stageless

Le payload **complet** est embarqué dès le départ.

```
┌────────────────────────────────────────────────────────────┐
│ Payload complet (tout inclus)                              │
│ - Keylogger                                                │
│ - Screenshot                                               │
│ - Shell                                                    │
│ - Persistence                                              │
│ - Etc.                                                     │
└────────────────────────────────────────────────────────────┘
```

**Avantages** :
- Fonctionne hors-ligne
- Moins de trafic réseau initial
- Plus résilient

**Inconvénients** :
- Fichier plus gros
- Plus facile à analyser

### Ghost C2 : Stageless
Notre agent `ghost.exe` est **stageless** : toutes les fonctionnalités sont embarquées.

---

## C2 (Command & Control)

### Qu'est-ce qu'un C2 ?

Le **C2** est l'infrastructure de contrôle qui permet à l'opérateur de :
- Envoyer des commandes aux agents
- Recevoir les résultats
- Gérer plusieurs implants

### Architecture Ghost C2

```
┌─────────────────┐         ┌─────────────────┐
│    Opérateur    │◀───────▶│   C2 Server     │
│    (CLI/Web)    │   API   │    (Go)         │
└─────────────────┘         └────────┬────────┘
                                     │
                                     │ HTTPS
                                     │ Beaconing
                                     ▼
                            ┌─────────────────┐
                            │   Agent         │
                            │   (ghost.exe)   │
                            │                 │
                            │ ┌─────────────┐ │
                            │ │ Keylogger   │ │
                            │ │ Screenshot  │ │
                            │ │ Shell       │ │
                            │ │ ...         │ │
                            │ └─────────────┘ │
                            └─────────────────┘
```

### Protocoles C2 courants

| Protocole | Avantages | Inconvénients |
|-----------|-----------|---------------|
| **HTTP/S** | Passe les firewalls | Peut être inspecté (SSL inspection) |
| **DNS** | Très discret | Lent, limité en bande passante |
| **ICMP** | Souvent autorisé | Anormal en volume |
| **DoH** | Chiffré, discret | Nouveau, peut être bloqué |
| **WebSocket** | Bidirectionnel, temps réel | Connexion persistante visible |

### MITRE ATT&CK
- **T1071** - Application Layer Protocol
- **T1573** - Encrypted Channel
- **T1571** - Non-Standard Port

---

## Techniques d'Évasion

### Anti-Debugging

Détecte si le programme est analysé dans un debugger.

```c
// Technique 1: IsDebuggerPresent
if (IsDebuggerPresent()) ExitProcess(0);

// Technique 2: NtQueryInformationProcess
DWORD isDebugged = 0;
NtQueryInformationProcess(GetCurrentProcess(), 
    ProcessDebugPort, &isDebugged, sizeof(isDebugged), NULL);
if (isDebugged) ExitProcess(0);

// Technique 3: Timing
DWORD t1 = GetTickCount();
// Code suspect
DWORD t2 = GetTickCount();
if (t2 - t1 > 1000) ExitProcess(0); // Trop lent = debugger
```

### Anti-Sandbox / Anti-VM

Détecte les environnements d'analyse automatique.

| Technique | Ce qu'on vérifie |
|-----------|------------------|
| **Hardware** | RAM < 4GB, 1 CPU, pas de GPU |
| **VM artifacts** | VMware Tools, VirtualBox Guest Additions |
| **Registry** | Clés spécifiques aux VMs |
| **MAC Address** | Préfixes connus (00:0C:29 = VMware) |
| **Timing** | Sleep qui sont accélérés |
| **User activity** | Pas de fichiers récents, pas de navigateur |

### Obfuscation de strings

```c
// MAUVAIS : String en clair
char* url = "http://evil.com/c2";  // Visible avec 'strings'

// MIEUX : String chiffrée
char encrypted[] = { 0x49, 0x5a, 0x5a, 0x51, ... };
xor_decrypt(encrypted, key);  // Déchiffre à runtime
```

### MITRE ATT&CK
- **T1497** - Virtualization/Sandbox Evasion
- **T1622** - Debugger Evasion
- **T1027** - Obfuscated Files

---

## Persistence

### Qu'est-ce que la Persistence ?

Techniques pour **survivre aux redémarrages** et maintenir l'accès.

### Méthodes courantes

| Méthode | Clé/Chemin | MITRE |
|---------|------------|-------|
| **Run Key** | `HKCU\...\Run` | T1547.001 |
| **Scheduled Task** | `schtasks /create` | T1053.005 |
| **Service** | `sc create` | T1543.003 |
| **Startup Folder** | `%APPDATA%\...\Startup` | T1547.001 |
| **WMI Event** | Subscription WMI | T1546.003 |
| **DLL Hijacking** | DLL dans PATH | T1574.001 |

### Implémentation Ghost C2

```c
// Notre fonction Persist_AddRunKey()
RegSetValueExA(
    HKEY_CURRENT_USER,
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "WindowsUpdate",  // Nom discret
    REG_SZ,
    path_to_agent,
    strlen(path_to_agent)
);
```

---

## Credential Access

### Objectif

Voler des identifiants pour élévation de privilèges ou mouvement latéral.

### Techniques implémentées dans Ghost C2

| Module | Cible | Technique |
|--------|-------|-----------|
| `browser.c` | Chrome passwords | DPAPI + SQLite |
| `lsass.c` | Hashes Windows | MiniDumpWriteDump |
| `lsass.c` | SAM/SYSTEM | RegSaveKey |
| `exfil.c` | Fichiers .kdbx | Recherche par extension |

### LSASS Dumping expliqué

```
┌─────────────────┐
│   lsass.exe     │  ◀── Contient les credentials en mémoire
│                 │
│  NTLM Hashes    │
│  Kerberos TGT   │
│  Plaintext PWD  │
└────────┬────────┘
         │
         │ MiniDumpWriteDump
         ▼
┌─────────────────┐
│   lsass.dmp     │  ◀── Fichier dump
└────────┬────────┘
         │
         │ mimikatz / pypykatz
         ▼
┌─────────────────┐
│   Credentials   │
│   en clair !    │
└─────────────────┘
```

### MITRE ATT&CK
- **T1003.001** - LSASS Memory
- **T1003.002** - SAM Database
- **T1555.003** - Credentials from Web Browsers

---

## Lateral Movement

### Objectif

Se déplacer vers d'autres machines du réseau.

### Techniques courantes

| Technique | Pré-requis | MITRE |
|-----------|------------|-------|
| **PsExec** | Admin + SMB | T1570 |
| **WMI** | Admin + WMI | T1047 |
| **WinRM** | Admin + WinRM | T1021.006 |
| **Pass-the-Hash** | NTLM Hash | T1550.002 |
| **RDP** | Credentials | T1021.001 |

### Exemple avec SOCKS Proxy (Ghost C2)

```
Opérateur                          Réseau cible
    │                                   │
    │   ┌───────────────┐               │
    ├──▶│ SOCKS5 Proxy  │◀──────────────┤
    │   │ (ghost.exe)   │               │
    │   └───────┬───────┘               │
    │           │                       │
    │           ▼                       │
    │   ┌───────────────┐   ┌───────────────┐
    │   │  Machine A    │   │  Machine B    │
    │   │  (compromise) │──▶│  (target)     │
    │   └───────────────┘   └───────────────┘

L'opérateur peut accéder à Machine B via le proxy SOCKS5 
qui tourne sur Machine A.
```

---

## Résumé des techniques Ghost C2

| Composant | Technique MITRE | ID |
|-----------|-----------------|-----|
| Keylogger | Input Capture | T1056.001 |
| Screenshot | Screen Capture | T1113 |
| Webcam | Video Capture | T1125 |
| Microphone | Audio Capture | T1123 |
| Browser Creds | Credentials from Password Stores | T1555.003 |
| LSASS Dump | LSASS Memory | T1003.001 |
| Registry Dump | Security Account Manager | T1003.002 |
| Persistence | Boot/Logon Autostart | T1547.001 |
| SOCKS Proxy | Proxy | T1090 |
| Port Forward | Port Forwarding | T1090.001 |
| File Exfil | Automated Collection | T1119 |
| HTTPS C2 | Encrypted Channel | T1573 |
| Anti-Debug | Debugger Evasion | T1622 |
| Anti-Sandbox | Virtualization Evasion | T1497 |

---

## Pour aller plus loin

1. **MITRE ATT&CK Navigator** : https://mitre-attack.github.io/attack-navigator/
2. **Red Team Operations** : Apprendre les TTPs des vrais attaquants
3. **Malware Development** : Comprendre comment fonctionnent les malwares
4. **Purple Team** : Combiner Red et Blue pour améliorer la sécurité

> **Rappel éthique** : Ces techniques sont présentées à des fins **éducatives** et pour **améliorer la sécurité défensive**. Leur utilisation non autorisée est illégale.
