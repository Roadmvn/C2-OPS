# C2 Communication Protocol

## Overview

The Ghost C2 uses a simple request-response protocol over HTTP/HTTPS. All traffic is:
1. JSON serialized
2. AES-256-CBC encrypted
3. Base64 encoded

## Message Flow

```
Agent                                 Server
  │                                     │
  │──── Checkin (agent info) ──────────>│
  │<─── Welcome response ───────────────│
  │                                     │
  │──── Get Tasks ─────────────────────>│
  │<─── Tasks list ─────────────────────│
  │                                     │
  │──── Task Result ───────────────────>│
  │<─── Acknowledgement ────────────────│
  │                                     │
```

## Encryption

### Key Exchange
Currently uses static keys embedded in the agent. In production:
- Use DH/ECDH for key exchange
- Rotate keys periodically

### AES-256-CBC Parameters
- **Key**: 32 bytes
- **IV**: 16 bytes  
- **Padding**: PKCS#7

## Message Formats

### Agent Request
```json
{
  "action": "checkin|get_tasks|result",
  "id": "agent-uuid",
  "data": { ... }
}
```

### Checkin Data
```json
{
  "hostname": "WORKSTATION",
  "username": "admin",
  "domain": "CORP",
  "os": "Windows 10.0 Build 19041",
  "arch": "x64",
  "pid": 1234,
  "elevated": false
}
```

### Task
```json
{
  "task_id": "uuid",
  "command": "shell",
  "args": "whoami"
}
```

### Task Result
```json
{
  "task_id": "uuid",
  "status": 0,
  "output": "CORP\\admin"
}
```

## Status Codes
- `0` - Success
- `1` - Failure
- `2` - Task error
