# Guide Complet du Chiffrement pour C2/Malware

## Table des matières
1. [Concepts de base](#concepts-de-base)
2. [XOR - La base](#xor---la-base)
3. [RC4 - Stream Cipher](#rc4---stream-cipher)
4. [AES - Block Cipher](#aes---block-cipher)
5. [ChaCha20 - Alternative moderne](#chacha20---alternative-moderne)
6. [RSA - Chiffrement asymétrique](#rsa---chiffrement-asymétrique)
7. [Comparaison et choix](#comparaison-et-choix)
8. [Implémentations pratiques](#implémentations-pratiques)

---

## Concepts de base

### Symétrique vs Asymétrique

```
┌─────────────────────────────────────────────────────────────┐
│                   CHIFFREMENT SYMÉTRIQUE                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Même clé pour chiffrer ET déchiffrer                      │
│                                                              │
│   Alice ──[clé secrète]──► Chiffre ──► "x#@$" ──►           │
│                                                              │
│   Bob   ◄──[clé secrète]── Déchiffre ◄── "x#@$" ◄──         │
│                                                              │
│   Exemples: AES, RC4, ChaCha20, XOR                         │
│   Problème: Comment partager la clé ?                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   CHIFFREMENT ASYMÉTRIQUE                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   2 clés différentes: publique + privée                     │
│                                                              │
│   Alice ──[clé PUBLIQUE Bob]──► Chiffre ──► "x#@$"          │
│                                                              │
│   Bob   ◄──[clé PRIVÉE Bob]─── Déchiffre ◄── "x#@$"         │
│                                                              │
│   Exemples: RSA, ECC, Diffie-Hellman                        │
│   Avantage: Pas besoin de partager de secret                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Stream Cipher vs Block Cipher

| Type | Fonctionnement | Exemples |
|------|----------------|----------|
| **Stream** | Chiffre octet par octet | RC4, ChaCha20 |
| **Block** | Chiffre par blocs (16 bytes) | AES, DES, 3DES |

---

## XOR - La base

### Pourquoi XOR ?

XOR est l'opération fondamentale de TOUT chiffrement car :
- **Réversible** : `A XOR B XOR B = A`
- **Simple** : Une seule opération CPU
- **Rapide** : Le plus rapide possible

### Table de vérité

```
A | B | A XOR B
--|---|--------
0 | 0 |    0
0 | 1 |    1
1 | 0 |    1
1 | 1 |    0
```

### Exemple visuel

```
Texte:     H    e    l    l    o
ASCII:    72  101  108  108  111
Binaire:  01001000 01100101 01101100 01101100 01101111

Clé:       K    E    Y    K    E  (répétée)
ASCII:    75   69   89   75   69
Binaire:  01001011 01000101 01011001 01001011 01000101

XOR:      00000011 00100000 00110101 00100111 00101010
Résultat:    3      32      53      39      42
Chiffré:  [caractères non imprimables]
```

### Code C

```c
void xor_encrypt(unsigned char* data, int len, unsigned char* key, int keylen) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

// Déchiffrement = même fonction (XOR est réversible)
#define xor_decrypt xor_encrypt
```

### Code Python

```python
def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# Exemple
encrypted = xor(b"Hello", b"KEY")
decrypted = xor(encrypted, b"KEY")  # = b"Hello"
```

### ⚠️ Faiblesses du XOR simple

- **Patterns visibles** si clé répétée et connue
- **Attaque known-plaintext** : si on connaît une partie du texte clair
- **Fréquence** : analyse statistique possible

---

## RC4 - Stream Cipher

### Qu'est-ce que RC4 ?

RC4 (Rivest Cipher 4) génère un **flux pseudo-aléatoire** (keystream) à partir d'une clé, puis XOR avec les données.

### Fonctionnement

```
┌─────────────────────────────────────────────────────────────┐
│                            RC4                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  PHASE 1: KSA (Key Scheduling Algorithm)                    │
│  ─────────────────────────────────────────                  │
│                                                              │
│  S[256] = {0, 1, 2, ..., 255}   // Tableau initial          │
│                                                              │
│  for i = 0 to 255:                                          │
│      j = (j + S[i] + key[i % keylen]) % 256                 │
│      swap(S[i], S[j])           // Mélange avec la clé      │
│                                                              │
│  PHASE 2: PRGA (Pseudo-Random Generation Algorithm)        │
│  ─────────────────────────────────────────────────          │
│                                                              │
│  for each byte of plaintext:                                │
│      i = (i + 1) % 256                                      │
│      j = (j + S[i]) % 256                                   │
│      swap(S[i], S[j])                                       │
│      K = S[(S[i] + S[j]) % 256]  // Octet du keystream      │
│      ciphertext += plaintext XOR K                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Code C complet

```c
typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX* ctx, unsigned char* key, int keylen) {
    int i, j = 0;
    unsigned char tmp;
    
    // Initialise S avec 0-255
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    // KSA: mélange S avec la clé
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keylen]) & 0xFF;
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
    
    ctx->i = ctx->j = 0;
}

void rc4_crypt(RC4_CTX* ctx, unsigned char* data, int len) {
    int i = ctx->i, j = ctx->j;
    unsigned char tmp, k;
    
    for (int n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + ctx->S[i]) & 0xFF;
        
        // Swap
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
        
        // Génère keystream byte
        k = ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];
        
        // XOR avec les données
        data[n] ^= k;
    }
    
    ctx->i = i;
    ctx->j = j;
}
```

### Code Python

```python
def rc4(data: bytes, key: bytes) -> bytes:
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # PRGA
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)
```

### Pourquoi RC4 dans les malwares ?

| Avantage | Détail |
|----------|--------|
| **~50 lignes** | Pas de dépendances |
| **Rapide** | Opérations simples |
| **Petit** | Pas de tables, pas de constantes |
| **Réversible** | Même code pour chiffrer/déchiffrer |

### ⚠️ Faiblesses connues

- **Biais dans les premiers octets** → Jeter les 256-1024 premiers octets
- **Clé réutilisée** = cassé
- **Attaques connues** (WEP, etc.)

---

## AES - Block Cipher

### Qu'est-ce que AES ?

**AES** (Advanced Encryption Standard) est le standard actuel. Chiffre par blocs de **16 bytes**.

### Modes d'opération

```
┌─────────────────────────────────────────────────────────────┐
│                         MODES AES                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ECB (Electronic Codebook) - À ÉVITER                       │
│  ────────────────────────────────────                       │
│  Bloc1 ──► AES ──► Chiffré1                                 │
│  Bloc2 ──► AES ──► Chiffré2   (mêmes blocs = même sortie!)  │
│                                                              │
│  CBC (Cipher Block Chaining) - OK                           │
│  ────────────────────────────────                           │
│  IV ─────────────┐                                          │
│                  ▼                                           │
│  Bloc1 ──► XOR ──► AES ──► Chiffré1 ─┐                      │
│                                       ▼                      │
│  Bloc2 ──► XOR ◄──────────────────────┘ ──► AES ──► Chiffré2│
│                                                              │
│  CTR (Counter) - Recommandé                                 │
│  ─────────────────────────                                  │
│  Nonce+Counter ──► AES ──► Keystream ──► XOR ──► Chiffré    │
│  (Transforme AES en stream cipher!)                         │
│                                                              │
│  GCM (Galois/Counter Mode) - Le meilleur                    │
│  ─────────────────────────────────────                      │
│  CTR + authentification intégrée (détecte modifications)    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Code Python (avec pycryptodome)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# === AES-CBC ===
def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> tuple:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ciphertext

def aes_cbc_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# === AES-GCM (recommandé) ===
def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> tuple:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def aes_gcm_decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Exemple
key = get_random_bytes(32)  # AES-256
nonce, encrypted, tag = aes_gcm_encrypt(b"Hello World", key)
decrypted = aes_gcm_decrypt(nonce, encrypted, tag, key)
```

### Code C (avec OpenSSL - plus complexe)

```c
#include <openssl/evp.h>

int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *key, unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}
```

---

## ChaCha20 - Alternative moderne

### Pourquoi ChaCha20 ?

- **Plus rapide** que AES sur CPU sans AES-NI
- **Plus simple** à implémenter
- **Aussi sécurisé** que AES
- Utilisé par Google (TLS), WireGuard, etc.

### Fonctionnement simplifié

```
┌─────────────────────────────────────────────────────────────┐
│                         ChaCha20                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  État initial (512 bits = 16 x 32-bit words):               │
│  ┌────────────────────────────────────────┐                 │
│  │ "expa" │ "nd 3" │ "2-by" │ "te k" │    │ Constantes      │
│  │  Key   │  Key   │  Key   │  Key   │    │ Clé (256 bits)  │
│  │  Key   │  Key   │  Key   │  Key   │    │                 │
│  │ Counter│ Nonce  │ Nonce  │ Nonce  │    │ Counter + Nonce │
│  └────────────────────────────────────────┘                 │
│                                                              │
│  20 rounds de:                                              │
│  - Quarter rounds (additions, XOR, rotations)               │
│  - Pas de tables = pas d'attaques timing                    │
│                                                              │
│  Sortie: 64 bytes de keystream                              │
│  → XOR avec plaintext                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Code Python

```python
from Crypto.Cipher import ChaCha20

def chacha20_encrypt(plaintext: bytes, key: bytes) -> tuple:
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce, ciphertext

def chacha20_decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)
```

---

## RSA - Chiffrement asymétrique

### Pourquoi RSA dans un C2 ?

On utilise RSA pour **échanger les clés symétriques** de manière sécurisée :

```
┌─────────────────────────────────────────────────────────────┐
│                  ÉCHANGE DE CLÉS AVEC RSA                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  SERVEUR C2                           AGENT                  │
│  ──────────                           ─────                  │
│  1. Génère paire RSA                                        │
│     (publique + privée)                                     │
│                                                              │
│  2. ──────── Clé publique ────────────►                     │
│                                                              │
│                                     3. Génère clé AES       │
│                                                              │
│                                     4. Chiffre clé AES      │
│                                        avec RSA publique    │
│                                                              │
│     ◄──────── Clé AES chiffrée ─────────                    │
│                                                              │
│  5. Déchiffre avec RSA privée                               │
│                                                              │
│  ══════════ Communications chiffrées en AES ═══════════     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Code Python

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Génération de clés (côté serveur)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Chiffrement (côté agent)
def rsa_encrypt(plaintext: bytes, public_key_pem: bytes) -> bytes:
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(plaintext)

# Déchiffrement (côté serveur)
def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)
```

---

## Comparaison et choix

### Tableau récapitulatif

| Algo | Type | Vitesse | Sécurité | Complexité | Usage C2 |
|------|------|---------|----------|------------|----------|
| **XOR** | - | ⚡⚡⚡⚡⚡ | ⚠️ Faible | 5 lignes | Obfuscation strings |
| **RC4** | Stream | ⚡⚡⚡⚡ | ⚠️ Obsolète | 50 lignes | Legacy, payloads |
| **AES-GCM** | Block | ⚡⚡⚡ | ✅ Fort | Lib externe | Communications |
| **ChaCha20** | Stream | ⚡⚡⚡⚡ | ✅ Fort | Lib externe | Alternative AES |
| **RSA** | Asymétrique | ⚡ | ✅ Fort | Lib externe | Échange de clés |

### Recommandation pour un C2

```
┌─────────────────────────────────────────────────────────────┐
│                   STACK CRYPTO RECOMMANDÉ                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. ÉCHANGE INITIAL                                         │
│     RSA-2048 ou ECDH (Diffie-Hellman courbes elliptiques)   │
│     → Établit une clé de session                            │
│                                                              │
│  2. COMMUNICATIONS                                          │
│     AES-256-GCM ou ChaCha20-Poly1305                        │
│     → Chiffrement + authentification                        │
│                                                              │
│  3. OBFUSCATION LOCALE                                      │
│     XOR ou RC4 pour les strings/shellcode en mémoire        │
│     → Simple, juste pour éviter analyse statique            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Implémentations pratiques

### Multi-couche (comme ton camarade)

```python
from Crypto.Cipher import AES, ARC4
from Crypto.Random import get_random_bytes

def multi_layer_encrypt(data: bytes, aes_key: bytes, rc4_key: bytes, xor_key: bytes) -> bytes:
    # Couche 1: XOR
    layer1 = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data))
    
    # Couche 2: RC4
    rc4 = ARC4.new(rc4_key)
    layer2 = rc4.encrypt(layer1)
    
    # Couche 3: AES-CBC
    iv = get_random_bytes(16)
    aes = AES.new(aes_key, AES.MODE_CBC, iv)
    # Padding manuel
    pad_len = 16 - (len(layer2) % 16)
    layer2_padded = layer2 + bytes([pad_len] * pad_len)
    layer3 = iv + aes.encrypt(layer2_padded)
    
    return layer3
```

### Simple et efficace (recommandé)

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def simple_encrypt(data: bytes, key: bytes) -> bytes:
    """AES-GCM = chiffrement + authentification en une seule couche"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext  # 12 + 16 + data bytes

def simple_decrypt(encrypted: bytes, key: bytes) -> bytes:
    nonce = encrypted[:12]
    tag = encrypted[12:28]
    ciphertext = encrypted[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

---

## Résumé

| Si tu veux... | Utilise... |
|---------------|------------|
| Obfusquer des strings | XOR |
| Payload simple sans dépendances | RC4 |
| Communications sécurisées | AES-GCM |
| Alternative rapide à AES | ChaCha20 |
| Échanger des clés | RSA ou ECDH |
| Faire "comme les pros" | AES-GCM + RSA pour key exchange |
