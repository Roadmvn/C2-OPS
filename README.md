# 👻 Ghost C2 Framework

A modular, stealthy Command and Control (C2) framework featuring:
- **Agent (Demon)**: Windows implant written in C with advanced evasion
- **Teamserver**: Go-based server with REST API and WebSocket
- **Web UI**: Modern React dashboard for operator control
- **Malleable Profiles**: Customizable traffic patterns

## 🏗️ Architecture

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

## 📁 Project Structure

```
c2-server/
├── agent/                    # Windows Agent (C)
│   ├── include/              # Headers
│   │   ├── common.h          # Common types and macros
│   │   └── ntdefs.h          # NT structures for syscalls
│   ├── src/
│   │   ├── core/             # Core agent logic
│   │   ├── crypto/           # AES, XOR, Base64
│   │   ├── evasion/          # Anti-debug, sandbox, syscalls
│   │   ├── network/          # HTTP transport, profiles
│   │   ├── tasks/            # Command handlers
│   │   └── utils/            # Memory, strings, PEB walking
│   └── Makefile              # Cross-compilation with MinGW
│
├── server/                   # Teamserver (Go)
│   ├── cmd/                  # Entry point
│   ├── internal/             # Private packages
│   │   ├── api/              # REST API (Gin)
│   │   ├── cli/              # Interactive console
│   │   ├── crypto/           # AES encryption
│   │   ├── listener/         # HTTP/HTTPS listeners
│   │   ├── profile/          # Malleable profile loader
│   │   ├── session/          # Agent session management
│   │   └── task/             # Task queue
│   └── pkg/                  # Public packages
│       └── protocol/         # Message definitions
│
├── web/                      # Web UI (React + Vite)
│   └── src/
│       ├── components/       # Layout, UI components
│       ├── pages/            # Dashboard, Agents, etc.
│       └── services/         # API client
│
├── profiles/                 # Malleable C2 profiles
│   ├── default.yaml          # Basic profile
│   ├── jquery.yaml           # jQuery CDN mimicry
│   └── microsoft.yaml        # Windows Update mimicry
│
└── docs/                     # Documentation
```

## 🚀 Quick Start

### Prerequisites

- **Go 1.21+** for the teamserver
- **MinGW-w64** for cross-compiling the agent
- **Node.js 18+** for the web UI

### Install Dependencies

```bash
# macOS - Install MinGW for cross-compilation
brew install mingw-w64

# Install Go dependencies
cd server && go mod download

# Install Web UI dependencies
cd web && npm install
```

### Build the Agent

```bash
cd agent

# Check MinGW is installed
make check

# Build EXE
make exe

# Build DLL
make dll

# Output: bin/ghost.exe, bin/ghost.dll
```

### Start the Teamserver

```bash
cd server

# Run with default settings
go run cmd/main.go

# With custom ports
go run cmd/main.go -api-port 3000 -listener-port 443 -profile profiles/jquery.yaml
```

### Start the Web UI (Development)

```bash
cd web

# Start dev server (proxies API to localhost:3000)
npm run dev

# Access at http://localhost:5173
```

## 🎮 Usage

### CLI Console Commands

```
ghost > help

Available Commands:
  agents/list          - List all connected agents
  use <id>             - Select an agent to interact with
  back                 - Deselect current agent
  tasks                - Show pending tasks for current agent

Agent Commands (requires selected agent):
  shell <cmd>          - Execute a shell command
  pwd                  - Print working directory
  cd <path>            - Change directory
  ls [path]            - List directory contents
  download <path>      - Download a file from target
  ps                   - List processes
  kill <pid>           - Kill a process
  whoami               - Get current user info
  sysinfo              - Get system information
  sleep <seconds>      - Change callback interval
```

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Dashboard statistics |
| `/api/agents` | GET | List all agents |
| `/api/agents/:id` | GET | Get agent details |
| `/api/agents/:id` | DELETE | Remove agent |
| `/api/agents/:id/task` | POST | Queue a task |
| `/api/agents/:id/tasks` | GET | Get agent's tasks |

## 🛡️ Agent Evasion Techniques

| Technique | Description |
|-----------|-------------|
| **PEB Walking** | Resolve APIs without GetProcAddress |
| **Indirect Syscalls** | Call NT functions directly, bypass hooks |
| **String Encryption** | XOR-encrypted strings at runtime |
| **Anti-Debugging** | PEB check, debug port, timing attacks |
| **Sandbox Detection** | CPU count, RAM, uptime, VM artifacts |
| **Sleep Obfuscation** | Encrypt memory during sleep (stub) |

## 🎨 Malleable Profiles

Profiles customize C2 traffic to blend with legitimate traffic:

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

## ⚠️ Disclaimer

**This project is for educational and authorized security testing purposes only.**

Unauthorized access to computer systems is illegal. Use this framework only on systems you own or have explicit permission to test. The authors are not responsible for misuse.

## 📄 License

This project is provided for educational purposes. See LICENSE for details.
