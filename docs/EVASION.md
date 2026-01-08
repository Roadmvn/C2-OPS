# Evasion Techniques

## Overview

The Ghost agent implements multiple evasion layers to avoid detection by security products.

## 1. PEB Walking

Instead of calling `GetProcAddress()` which can be hooked, we walk the Process Environment Block (PEB) to find loaded modules and their exports.

```c
// Get module by hash instead of name
HMODULE ntdll = peb_get_module(HASH_NTDLL_DLL);

// Get function by hash
FARPROC func = peb_get_proc(ntdll, HASH_NTALLOCATEVIRTUALMEMORY);
```

**Why**: EDRs hook `GetProcAddress` to monitor API resolution.

## 2. Indirect Syscalls

Instead of calling NTDLL functions (which may be hooked), we:
1. Parse NTDLL to find syscall numbers
2. Execute syscalls directly

```c
// Pattern to find syscall number
// mov r10, rcx      ; 4C 8B D1
// mov eax, <num>    ; B8 XX XX 00 00
```

**Why**: User-mode hooks in NTDLL are bypassed.

## 3. String Encryption

All strings are XOR-encrypted and decrypted at runtime:

```c
// Instead of: char* url = "https://c2.example.com";
// We use encrypted bytes that are decrypted in memory
static uint8_t ENCRYPTED_URL[] = { 0x.. };
decrypt_string(ENCRYPTED_URL, sizeof(ENCRYPTED_URL));
```

**Why**: Static analysis won't find suspicious strings.

## 4. Anti-Debugging

Multiple checks to detect debuggers:

| Check | Method |
|-------|--------|
| PEB BeingDebugged | Direct PEB access |
| Debug Port | NtQueryInformationProcess |
| Debug Flags | NtQueryInformationProcess |
| Debug Object | NtQueryInformationProcess |
| Timing | Performance counter |
| Process List | Check for ollydbg, x64dbg, etc. |

## 5. Sandbox Detection

Scoring system to detect VMs/sandboxes:

| Check | Points | Threshold |
|-------|--------|-----------|
| CPU count < 2 | +1 | |
| RAM < 2GB | +1 | |
| Uptime < 30min | +2 | |
| Disk < 60GB | +1 | |
| Process count < 50 | +1 | |
| VM registry keys | +3 | |
| VM files/drivers | +3 | |
| VM MAC prefix | +2 | |
| Suspicious hostname | +2 | |

**Total >= 4** → Likely sandbox

## 6. Sleep Obfuscation (Ekko)

During sleep, the agent is vulnerable to memory scans. Full implementation would:

1. Capture execution context
2. Create a timer callback
3. Encrypt memory with AES
4. Sleep
5. Timer fires, decrypts memory
6. Resume execution

**Current status**: Stub implementation, uses basic sleep.

## 7. AMSI/ETW Bypass (TODO)

Future improvements:
- Patch `AmsiScanBuffer` to return clean
- Disable ETW tracing

## Recommendations

For maximum evasion:
1. Compile with different keys for each payload
2. Use HTTPS with valid certificate
3. Use a CDN-matching profile (jquery, microsoft)
4. Set long sleep intervals (5+ minutes)
5. Avoid running common commands immediately
