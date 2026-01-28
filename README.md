# Ghost C2

A modular C2 framework for red team operations and security research.

**Components:**
- **Agent** - Windows implant in pure C. No .NET, no PowerShell, direct syscalls.
- **Teamserver** - Go backend handling sessions, tasks, and listeners.
- **Web UI** - React dashboard for visual management.
- **Malleable Profiles** - Customize traffic to mimic legitimate services.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                            OPERATOR                              │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐         │
│  │    Web UI     │  │  CLI Console  │  │   REST API    │         │
│  │    (React)    │  │   (Terminal)  │  │    (HTTP)     │         │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘         │
│          │                  │                  │                 │
│          └──────────────────┼──────────────────┘                 │
│                             │                                    │
│  ┌──────────────────────────▼───────────────────────────────┐    │
│  │                    TEAMSERVER (Go)                       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                │    │
│  │  │ Sessions │  │  Tasks   │  │ Profiles │                │    │
│  │  └──────────┘  └──────────┘  └──────────┘                │    │
│  │  ┌───────────────────────────────────────────────────┐   │    │
│  │  │              HTTP/HTTPS Listener                  │   │    │
│  │  └───────────────────────────────────────────────────┘   │    │
│  └──────────────────────────┬───────────────────────────────┘    │
└─────────────────────────────┼────────────────────────────────────┘
                              │ (Encrypted C2 Traffic)
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│                        TARGET NETWORK                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     GHOST AGENT (C)                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │  │
│  │  │  Evasion │  │  Crypto  │  │   Tasks  │  │  Network │    │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Project Layout

```
C2-OPS/
├── agent/                    # Windows implant (C)
│   ├── include/              # Headers (common.h, ntdefs.h)
│   │   ├── credentials/      # Browser, LSASS headers
│   │   ├── exfil/            # File exfiltration
│   │   ├── network/          # SOCKS5, port forward
│   │   ├── recon/            # Scanner
│   │   ├── remote/           # Desktop capture
│   │   └── surveillance/     # Keylogger, screenshot, webcam, mic
│   ├── src/
│   │   ├── core/             # Main loop, config, auth
│   │   ├── crypto/           # AES, XOR, Base64
│   │   ├── evasion/          # Anti-debug, sandbox, syscalls, sleep
│   │   ├── network/          # HTTP transport, profiles, SOCKS5, portfwd
│   │   ├── tasks/            # Command handlers
│   │   │   └── handlers/     # Shell, file, process, recon, token, persist
│   │   ├── credentials/      # Browser passwords, LSASS dump
│   │   ├── surveillance/     # Keylogger, screenshot, clipboard, webcam, mic
│   │   ├── remote/           # Remote desktop
│   │   ├── exfil/            # File exfiltration
│   │   ├── recon/            # Port scanner
│   │   └── utils/            # Memory, strings, PEB walking
│   └── Makefile
│
├── server/                   # Teamserver (Go)
│   ├── cmd/                  # main.go
│   ├── internal/
│   │   ├── api/              # REST router
│   │   ├── auth/             # Agent validation
│   │   ├── cli/              # Console interface
│   │   ├── crypto/           # AES encryption
│   │   ├── handlers/         # Command handlers
│   │   ├── listener/         # HTTP listener
│   │   ├── profile/          # Malleable profiles
│   │   ├── session/          # Agent sessions
│   │   └── task/             # Task queue
│   └── pkg/protocol/         # Message structs
│
├── web/                      # Dashboard (React + Vite)
│   └── src/
│
├── profiles/                 # Traffic profiles (YAML)
│   ├── default.yaml
│   ├── jquery.yaml           # CDN traffic
│   └── microsoft.yaml        # Windows Update
│
├── guides/                   # Documentation
└── docs/                     # Protocol & evasion docs
```

## Requirements

| Component | Language | Target Platform | Build Platform |
|-----------|----------|-----------------|----------------|
| **Agent** | C | Windows x64 | Mac/Linux (MinGW cross-compile) |
| **Server** | Go | Any | Any |
| **Web UI** | React | Browser | Any |

## Setup

### Dependencies

```bash
# macOS
brew install mingw-w64 go node

# Ubuntu/Debian
apt install mingw-w64 golang nodejs npm
```

### Build

```bash
# Server dependencies
cd server && go mod download

# Web UI dependencies
cd web && npm install

# Build agent
cd agent
make check    # Verify MinGW
make exe      # -> bin/ghost.exe
make dll      # -> bin/ghost.dll
```

### Run

```bash
# Start teamserver
cd server
go run cmd/main.go -api-port 3000 -listener-port 443

# Start web UI
cd web
npm run dev   # http://localhost:5173
```

## Commands

### Basic Operations

| Command | Description |
|---------|-------------|
| `shell <cmd>` | Execute shell command |
| `pwd` | Print working directory |
| `cd <path>` | Change directory |
| `ls [path]` | List files |

### File Operations

| Command | Description |
|---------|-------------|
| `download <file>` | Download file from target |
| `upload <file>` | Upload file to target |

### Process Management

| Command | Description |
|---------|-------------|
| `ps` | List processes |
| `kill <pid>` | Terminate process |

### Reconnaissance

| Command | Description |
|---------|-------------|
| `whoami` | User info (name, domain, privileges) |
| `sysinfo` | System info (OS, arch, hostname, IPs) |

### Token Manipulation

| Command | Description |
|---------|-------------|
| `token_list` | List available tokens |
| `token_steal <pid>` | Steal token from process |

### Surveillance

| Command | Description |
|---------|-------------|
| `screenshot` | Capture screen |
| `keylog_start` | Start keylogger |
| `keylog_stop` | Stop keylogger |
| `keylog_dump` | Get captured keystrokes |
| `clipboard_start` | Start clipboard monitor |
| `clipboard_stop` | Stop clipboard monitor |
| `clipboard_dump` | Get clipboard history |
| `webcam_snap` | Capture webcam image |
| `mic_record [seconds]` | Record microphone (default: 5s) |

### Remote Desktop

| Command | Description |
|---------|-------------|
| `desktop_capture [quality]` | Capture screen frame (1-100) |
| `desktop_mouse <x,y,flags>` | Inject mouse event |
| `desktop_key <vk,up>` | Inject keyboard event |

### Credential Extraction

| Command | Description |
|---------|-------------|
| `browser_creds` | Extract browser passwords |
| `browser_cookies` | Extract browser cookies |
| `lsass_dump` | Dump LSASS memory |
| `sam_dump` | Dump SAM hive |
| `system_dump` | Dump SYSTEM hive |
| `reg_creds` | Extract registry credentials |

### File Exfiltration

| Command | Description |
|---------|-------------|
| `exfil_search [path,byExt,byKey,depth]` | Search sensitive files |
| `exfil_read <file>` | Read file for exfiltration |

### Network Tools

| Command | Description |
|---------|-------------|
| `socks5_start [port]` | Start SOCKS5 proxy |
| `socks5_stop` | Stop SOCKS5 proxy |
| `portfwd_add <local,host,remote>` | Create port forward |
| `portfwd_remove <id>` | Remove port forward |
| `portfwd_list` | List port forwards |
| `scan_ports <target>` | Scan common ports |
| `scan_range <target,start,end>` | Scan port range |
| `scan_host <target>` | Check if host is up |

### Agent Control

| Command | Description |
|---------|-------------|
| `sleep <seconds>` | Set beacon interval |
| `persist [method]` | Add persistence |
| `exit` | Clean agent shutdown |
| `self_destruct` | Remove all traces and exit |

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Dashboard statistics |
| `/api/agents` | GET | List agents |
| `/api/agents/:id` | GET | Agent details |
| `/api/agents/:id` | DELETE | Remove agent |
| `/api/agents/:id/task` | POST | Send command |
| `/api/agents/:id/tasks` | GET | Task history |

## Evasion Techniques

| Technique | Description |
|-----------|-------------|
| PEB Walking | Resolve APIs without GetProcAddress |
| Indirect Syscalls | Bypass ntdll hooks |
| String Encryption | XOR strings at runtime |
| Anti-Debug | PEB flags, timing checks, debug port detection |
| Sandbox Detection | CPU count, RAM, uptime, VM artifacts |
| Sleep Obfuscation | Encrypt heap during sleep |
| Malleable Profiles | Mimic legitimate traffic patterns |

## Malleable Profiles

Example profile mimicking jQuery CDN traffic:

```yaml
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

## Legal Notice

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any system or network. Unauthorized use is prohibited and may violate applicable laws.

## Author

xAPT42

## License

For educational and authorized testing purposes only.
