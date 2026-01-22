# Réponses - Concepts OS & C2

## Cryptographie

### C'est quoi RC4 ?

**RC4** (Rivest Cipher 4) est un algorithme de chiffrement par flux (stream cipher) créé par Ron Rivest en 1987.

#### Fonctionnement simplifié

```
┌─────────────────────────────────────────────────────────────┐
│                         RC4                                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Clé (ex: "password")                                      │
│         │                                                    │
│         ▼                                                    │
│   ┌─────────────┐                                           │
│   │    KSA      │  Key Scheduling Algorithm                 │
│   │  (init S)   │  → Mélange un tableau de 256 octets       │
│   └─────────────┘                                           │
│         │                                                    │
│         ▼                                                    │
│   ┌─────────────┐                                           │
│   │    PRGA     │  Pseudo-Random Generation Algorithm       │
│   │ (keystream) │  → Génère un flux pseudo-aléatoire        │
│   └─────────────┘                                           │
│         │                                                    │
│         ▼                                                    │
│   Texte clair  XOR  Keystream  =  Texte chiffré             │
│   "Hello"      XOR  [A3 F2..]  =  [chiffré]                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### Code simplifié (pseudo-code)

```c
// Phase 1: Key Scheduling (KSA)
S[256] = {0, 1, 2, ..., 255}  // tableau de 0 à 255
j = 0
for i = 0 to 255:
    j = (j + S[i] + key[i % key_len]) % 256
    swap(S[i], S[j])

// Phase 2: Génération du keystream (PRGA)
i = j = 0
for each byte in plaintext:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    swap(S[i], S[j])
    K = S[(S[i] + S[j]) % 256]  // octet du keystream
    ciphertext += plaintext[byte] XOR K
```

#### Pourquoi RC4 est populaire dans les malwares ?

| Avantage | Explication |
|----------|-------------|
| **Simple à implémenter** | ~50 lignes de code, pas de dépendances |
| **Rapide** | Que des opérations simples (swap, XOR, modulo) |
| **Petit footprint** | Pas besoin de libs crypto lourdes |
| **Pas de padding** | Chiffre octet par octet |
| **Bi-directionnel** | Le même code chiffre et déchiffre |

#### ⚠️ Pourquoi c'est "obsolète" en sécurité

- **Biais statistiques** dans les premiers octets du keystream
- **Vulnérable** si on réutilise la même clé
- **Cassé** pour WEP/WPA (attaques connues)

#### Utilisation typique dans un C2

```c
// Chiffrer les communications agent ↔ serveur
char* encrypt_beacon(char* data, char* key) {
    rc4_init(key);
    return rc4_crypt(data);  // XOR avec keystream
}

// Même fonction pour déchiffrer (XOR est réversible)
char* decrypt_beacon(char* data, char* key) {
    rc4_init(key);
    return rc4_crypt(data);
}
```

#### Alternatives modernes

| Algo | Type | Notes |
|------|------|-------|
| **ChaCha20** | Stream cipher | Plus sécurisé, aussi rapide |
| **AES-GCM** | Block cipher | Standard, authentifié |
| **XOR simple** | Obfuscation | Encore plus simple, moins sécurisé |

---

## Composants Malware

### C'est quoi un Loader ?

Un **loader** est un programme dont le seul but est de **charger et exécuter** du code (shellcode, DLL, exe) en mémoire.

```
┌─────────────────────────────────────────────────────────────┐
│                        LOADER                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   1. Récupère le payload (embarqué, téléchargé, déchiffré)  │
│                          │                                   │
│                          ▼                                   │
│   2. Alloue de la mémoire exécutable (VirtualAlloc RWX)     │
│                          │                                   │
│                          ▼                                   │
│   3. Copie le payload en mémoire                            │
│                          │                                   │
│                          ▼                                   │
│   4. Exécute (CreateThread, callback, jump)                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Code typique d'un loader :**
```c
// 1. Payload chiffré (évite détection statique)
unsigned char shellcode[] = { 0x4d, 0x5a, ... };

// 2. Déchiffre
xor_decrypt(shellcode, key);

// 3. Alloue mémoire exécutable
void* mem = VirtualAlloc(NULL, sizeof(shellcode), 
                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// 4. Copie
memcpy(mem, shellcode, sizeof(shellcode));

// 5. Exécute
((void(*)())mem)();
```

---

### C'est quoi un Dropper ?

Un **dropper** est un programme qui **dépose (drop)** un fichier malveillant sur le disque puis l'exécute.

```
┌─────────────────────────────────────────────────────────────┐
│                       DROPPER                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Dropper.exe                                               │
│       │                                                      │
│       ├──► Extrait payload.exe (depuis ressources)          │
│       │                                                      │
│       ├──► Écrit sur disque: C:\Temp\payload.exe            │
│       │                                                      │
│       └──► Exécute: CreateProcess("payload.exe")            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| Loader | Dropper |
|--------|---------|
| Exécute **en mémoire** | Écrit **sur disque** |
| Plus discret | Laisse des traces |
| "Fileless" | Fichier analysable |

---

### C'est quoi Stager vs Stageless ?

```
┌─────────────────────────────────────────────────────────────┐
│                    STAGER (multi-étapes)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Stage 0 (petit, ~500 bytes)                               │
│       │                                                      │
│       ├──► Contacte le C2                                   │
│       │                                                      │
│       ├──► Télécharge Stage 1 (gros payload)                │
│       │                                                      │
│       └──► Exécute Stage 1 en mémoire                       │
│                                                              │
│   Avantages:                                                │
│   - Payload initial très petit (passe mieux)                │
│   - Payload final jamais sur disque                         │
│   - Peut mettre à jour le stage 1                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   STAGELESS (tout-en-un)                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Payload complet (~300 KB)                                 │
│       │                                                      │
│       └──► Exécute directement, pas de téléchargement       │
│                                                              │
│   Avantages:                                                │
│   - Pas de connexion réseau initiale                        │
│   - Fonctionne même si C2 down au départ                    │
│   - Plus simple                                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

### C'est quoi un Packer/Crypter ?

Un **packer** compresse et/ou chiffre un exe pour :
1. Réduire sa taille
2. Obfusquer son contenu
3. Éviter la détection par signature

```
┌─────────────────────────────────────────────────────────────┐
│                    PACKER / CRYPTER                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   malware.exe (détecté par AV)                              │
│       │                                                      │
│       ▼                                                      │
│   ┌─────────────────────────────────────────┐               │
│   │           PACKER                         │               │
│   │   1. Compresse le code original         │               │
│   │   2. Chiffre avec une clé               │               │
│   │   3. Ajoute un stub de décompression    │               │
│   └─────────────────────────────────────────┘               │
│       │                                                      │
│       ▼                                                      │
│   packed.exe (pas détecté... pour l'instant)                │
│                                                              │
│   À l'exécution:                                            │
│   packed.exe ──► déchiffre ──► décompresse ──► exécute      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Comment fonctionne la détection AV ?

### Les 3 types de détection

```
┌─────────────────────────────────────────────────────────────┐
│              MÉTHODES DE DÉTECTION ANTIVIRUS                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. STATIQUE (avant exécution)                              │
│     ├── Signatures: hash du fichier, patterns d'octets     │
│     ├── Heuristique: analyse du code (imports suspects)    │
│     └── Entropy: fichiers très compressés = suspect        │
│                                                              │
│  2. DYNAMIQUE (pendant exécution)                           │
│     ├── Sandbox: exécute dans une VM isolée                │
│     ├── Comportement: surveille les actions suspectes      │
│     └── API hooking: intercepte les appels système         │
│                                                              │
│  3. CLOUD/ML                                                │
│     ├── Envoie les fichiers suspects au cloud              │
│     └── Machine learning sur les comportements             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Comment bypass chaque type ?

| Type | Technique de bypass |
|------|---------------------|
| **Signatures** | Chiffrement, polymorphisme, recompilation |
| **Heuristique** | Indirect syscalls, API obfuscation |
| **Sandbox** | Détection VM, sleep long, interaction user |
| **Comportemental** | Injection dans process légitime |
| **Hooking** | Syscalls directs, unhooking ntdll |

### EDR vs AV

| AV Traditionnel | EDR (Endpoint Detection & Response) |
|-----------------|-------------------------------------|
| Focus sur les fichiers | Focus sur les comportements |
| Signatures | Machine learning + télémétrie |
| Bloque à l'exécution | Détecte + répond + forensics |
| Facile à bypass | Plus difficile à bypass |

---

*À compléter avec d'autres réponses...*
