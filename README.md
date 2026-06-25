# ShadowHook - Advanced EDR/AV Bypass Framework

> "Bypass EDR. Execute Shellcode. Remain Undetected."

---

## Disclaimer

This tool is for educational and research purposes only. Use only in authorized environments. The author is not responsible for any misuse.

---

## Description

ShadowHook is an advanced Red Team EDR/AV evasion framework that leverages Indirect Syscalls with Return Address Spoofing, IAT Hooking, and dynamic SSN Resolution to achieve FUD (Fully Undetectable) shellcode execution against Windows Defender, CrowdStrike, SentinelOne, Cylance, and BitDefender.

---

## Features

- Indirect Syscalls with Return Address Spoofing
- IAT Hooking (intercepts API calls before ntdll.dll)
- Dynamic SSN Resolution (no hardcoded values)
- XOR Encryption with random keys
- Anti-Debug & Anti-Sandbox
- FUD Shellcode Execution
- Custom Payload Support


## Quick Start

### Prerequisites

| Tool | Purpose |
|------|---------|
| MinGW-w64 | C compiler for Windows targets |
| NASM | Assembler for x64 assembly code |
| Make | Build automation |

### Install on Linux (Kali/Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y gcc-mingw-w64-x86-64 nasm make

```
### Build & Run ###

``` bash
git clone https://github.com/0xEv3nthorizon/ShadowHook.git
cd ShadowHook
make clean
make
```
### Run (Windows) ###

``` bash
ShadowHook.exe
```
### Run (Linux with Wine) ###

``` bash
sudo apt install wine
wine game.exe
```

### Custom Shellcode ###
Replace the shellcode in src/main.c:
``` bash
BYTE custom_shellcode[] = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
    // your shellcode here
};
```

### Demo Output ###

``` bash
┌─────────────────────────────────────────────────────────────┐
│  [+] ShadowHook v2.0 - Red Team EDR Evasion                │
│  [+] Running with elevated privileges                      │
│  [+] Windows 10 detected (Build: 19045)                   │
│  [+] ntdll base: 0x00007ffd2fe50000                       │
│  [+] syscall gadget: 0x00007ffd2feed5a2                   │
│  [+] HookChain initialized                                 │
│  [+] 6 hooks enabled successfully                          │
│  [+] SUCCESS: Memory allocated at: 0x0000025411220000     │
│  [+] SUCCESS: Shellcode executed at: 0x0000025411230000   │
│  [+] Done! Exiting...                                      │
└─────────────────────────────────────────────────────────────┘
```



























