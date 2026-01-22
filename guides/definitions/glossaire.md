# Glossaire & Définitions - Concepts C2/Malware

## Table des matières
- [Obfuscation](#obfuscation)
- [Packing](#packing)
- [Crypter](#crypter)
- [Shellcode](#shellcode)
- [Loader](#loader)
- [Dropper](#dropper)
- [Stager](#stager)
- [Beacon](#beacon)
- [Implant / Agent](#implant--agent)
- [C2 / C&C](#c2--cc)
- [Payload](#payload)
- [Persistence](#persistence)
- [Injection](#injection)
- [Hooking](#hooking)
- [Syscall](#syscall)
- [EDR / AV](#edr--av)

---

## Obfuscation

### Définition
**L'obfuscation** est le processus de rendre du code difficile à comprendre pour un humain ou un outil d'analyse, tout en conservant sa fonctionnalité.

### Types d'obfuscation

| Type | Description | Exemple |
|------|-------------|---------|
| **Code** | Modifier la structure du code | Control flow, dead code |
| **Données** | Cacher les strings/constantes | XOR, base64, stack strings |
| **Réseau** | Cacher le trafic C2 | Domain fronting, jitter |
| **Binaire** | Modifier le PE/ELF | Strip symbols, anti-disasm |

### Exemple concret

```c
// ❌ AVANT (lisible)
char* url = "http://evil.com";
WinHttpConnect(url);

// ✅ APRÈS (obfusqué)
char enc[] = {0x3a, 0x2b, 0x2b, 0x20...};  // XOR encoded
char* url = xor_decode(enc, key);
pWinHttpConnect fn = resolve_api("WinHttpConnect");
fn(url);
```

### Pourquoi obfusquer ?
- Éviter la détection par signature
- Ralentir l'analyse manuelle
- Cacher les IOCs (URLs, IPs, strings)

---

## Packing

### Définition
Le **packing** consiste à compresser et/ou chiffrer un exécutable, puis l'emballer avec un "stub" qui le décompresse/déchiffre à l'exécution.

### Comment ça marche

```
┌─────────────────────────────────────────────────────────────┐
│                     PACKING                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  AVANT:                                                     │
│  malware.exe (100 KB, détecté)                              │
│                                                              │
│  PROCESSUS:                                                 │
│  1. Compresser le code (LZMA, zlib)                         │
│  2. Optionnel: chiffrer                                     │
│  3. Ajouter un stub (décompresseur)                         │
│                                                              │
│  APRÈS:                                                     │
│  packed.exe (60 KB, pas détecté... peut-être)              │
│                                                              │
│  À L'EXÉCUTION:                                             │
│  stub → décompresse → écrit en mémoire → exécute           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Packers connus
| Packer | Type | Détection |
|--------|------|-----------|
| **UPX** | Open source | 🔴 Très détecté |
| **Themida** | Commercial | 🟠 Moyennement |
| **VMProtect** | Commercial | 🟠 Moyennement |
| **Custom** | DIY | 🟢 Moins détecté |

### ⚠️ Problème du packing en 2024
- Les AV détectent les packers connus
- Haute entropy = suspect
- Les sandbox attendent le dépack

---

## Crypter

### Définition
Un **crypter** est similaire à un packer mais se concentre sur le **chiffrement** plutôt que la compression. Le but est de rendre le code illisible pour les AV.

### Différence Packer vs Crypter

| Aspect | Packer | Crypter |
|--------|--------|---------|
| **Focus** | Compression | Chiffrement |
| **Taille** | Réduite | Peut augmenter |
| **But** | Réduire + obscurcir | Éviter détection |
| **Stub** | Décompresse | Déchiffre |

---

## Shellcode

### Définition
**Shellcode** = code machine brut (opcodes) qui peut s'exécuter indépendamment, sans dépendances externes.

### Caractéristiques
- Position-indépendant (PIC)
- Pas d'imports fixes
- Résout ses propres APIs
- Petit et autonome

### Exemple
```
\xfc\x48\x83\xe4\xf0\x...  // Bytes bruts
```

### Utilisations
- Payload d'exploit
- Injection en mémoire
- Stage initial d'un agent

---

## Loader

### Définition
Un **loader** est un programme dont le seul but est de charger et exécuter du code en mémoire.

### Workflow
```
1. Loader démarre
2. Récupère le payload (embarqué, téléchargé, ou déchiffré)
3. Alloue mémoire exécutable (VirtualAlloc RWX)
4. Copie le payload
5. Exécute (CreateThread, callback, jump)
6. Le loader peut se terminer
```

### Différence avec Dropper
- **Loader** = exécute en **mémoire**
- **Dropper** = écrit sur **disque** puis exécute

---

## Dropper

### Définition
Un **dropper** est un programme qui extrait un autre fichier malveillant, l'écrit sur disque, puis l'exécute.

### Workflow
```
1. Dropper démarre
2. Extrait le payload (depuis ressources, chiffré dans le code)
3. Écrit sur disque: C:\Temp\payload.exe
4. Exécute: CreateProcess("payload.exe")
5. Optionnel: se supprime lui-même
```

---

## Stager

### Définition
Un **stager** est un petit payload initial qui télécharge et exécute un payload plus gros (le "stage").

### Stager vs Stageless

```
┌─────────────────────────────────────────────────────────────┐
│  STAGER (multi-étapes)          STAGELESS (tout-en-un)     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Stage 0: ~500 bytes            Payload: ~300 KB            │
│  ↓ contacte C2                  ↓ exécute directement       │
│  ↓ télécharge Stage 1                                       │
│  Stage 1: ~300 KB                                           │
│                                                              │
│  ✅ Petit payload initial       ✅ Pas de téléchargement    │
│  ✅ Payload final jamais disque ✅ Marche si C2 down        │
│  ❌ Nécessite connexion C2      ❌ Plus gros à livrer       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Beacon

### Définition
Le **beaconing** est quand l'agent contacte périodiquement le serveur C2 pour récupérer des commandes.

### Paramètres importants
| Paramètre | Description |
|-----------|-------------|
| **Sleep** | Intervalle entre les beacons (ex: 60 sec) |
| **Jitter** | Variation aléatoire (ex: ±25%) |

### Exemple
```
Sleep: 60 sec, Jitter: 25%
→ Beacon entre 45 et 75 secondes (aléatoire)
```

---

## Implant / Agent

### Définition
L'**implant** ou **agent** est le logiciel qui s'exécute sur la machine victime et communique avec le C2.

### Synonymes
- Implant
- Agent
- Beacon (Cobalt Strike)
- Demon (Havoc)
- Ghost (ce projet)

---

## C2 / C&C

### Définition
**C2** (Command & Control) ou **C&C** est l'infrastructure qui contrôle les agents.

### Composants
```
┌─────────────────┐     ┌──────────────┐     ┌────────────┐
│   Opérateur     │────►│  Teamserver  │────►│   Agents   │
│   (Web UI)      │     │   (serveur)  │     │  (cibles)  │
└─────────────────┘     └──────────────┘     └────────────┘
```

---

## Payload

### Définition
**Payload** = le code malveillant qui sera exécuté. Peut être un shellcode, un exe, une DLL, un script, etc.

---

## Persistence

### Définition
**Persistence** = mécanismes pour survivre au reboot et rester sur le système.

### Exemples
- Registry Run keys
- Scheduled Tasks
- Services
- COM Hijacking
- WMI Event Subscription

---

## Injection

### Définition
**Injection** = exécuter du code dans le contexte d'un autre processus.

### Techniques principales
| Technique | Description |
|-----------|-------------|
| CreateRemoteThread | Créer un thread dans un autre process |
| Process Hollowing | Remplacer le code d'un process |
| APC Injection | Via Asynchronous Procedure Calls |
| DLL Injection | Charger une DLL dans un process |

---

## Hooking

### Définition
**Hooking** = intercepter des appels de fonctions pour les modifier ou les surveiller.

### Types
| Type | Niveau | Utilisé par |
|------|--------|-------------|
| **IAT Hook** | Import table | Malware, AV |
| **Inline Hook** | Début de fonction | EDR, malware |
| **Syscall Hook** | Niveau kernel | EDR |

### Exemple EDR
```
ntdll!NtWriteVirtualMemory:
  jmp EDR_Hook_Function    ← Hook inséré par l'EDR
  ...code original...
```

---

## Syscall

### Définition
**Syscall** = appel direct au kernel Windows, sans passer par les DLLs (ntdll.dll).

### Pourquoi les syscalls directs ?
- Bypass les hooks EDR sur ntdll
- Plus difficile à détecter

### Normal vs Direct
```
NORMAL:
VirtualAlloc → kernel32 → ntdll (HOOKED) → kernel

DIRECT:
syscall instruction → kernel (bypass hooks)
```

---

## EDR / AV

### Définitions

| Terme | Signification | Focus |
|-------|---------------|-------|
| **AV** | Antivirus | Fichiers, signatures |
| **EDR** | Endpoint Detection & Response | Comportement, telemetry |

### Différences

| Aspect | AV traditionnel | EDR |
|--------|-----------------|-----|
| Détection | Signatures | Comportement + ML |
| Réponse | Bloquer/Quarantine | Alerter + Forensics |
| Visibilité | Fichiers | Process, network, memory |
| Bypass | Relativement facile | Plus difficile |

---

## Résumé visuel

```
┌─────────────────────────────────────────────────────────────┐
│                    VUE D'ENSEMBLE                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  LIVRAISON                                                  │
│  Dropper ──► écrit Loader sur disque                        │
│  Loader ──► charge Shellcode en mémoire                     │
│  Stager ──► télécharge Agent complet                        │
│                                                              │
│  ÉVASION                                                    │
│  Obfuscation ──► code difficile à lire                      │
│  Packing ──► compresse/chiffre l'exe                        │
│  Crypter ──► chiffre pour éviter AV                         │
│                                                              │
│  EXÉCUTION                                                  │
│  Injection ──► code dans autre process                      │
│  Syscalls ──► bypass hooks EDR                              │
│                                                              │
│  COMMUNICATION                                              │
│  Agent/Implant ──► s'exécute sur cible                      │
│  Beacon ──► contacte C2 périodiquement                      │
│  C2 ──► contrôle les agents                                 │
│                                                              │
│  SURVIE                                                     │
│  Persistence ──► survit au reboot                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
