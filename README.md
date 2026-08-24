# NetRecon

> **Now on the Microsoft Store:** [NetRecon Network Toolkit](https://apps.microsoft.com/store/detail/9N0FM1DQSB34?cid=DevShareMCLPCS) - one-click install, automatic updates, no command line required.

NetRecon is a Python network reconnaissance toolkit built for fast DNS lookups, async TCP port scanning, optional Nmap-driven enumeration, IP geolocation, and exportable scan history. The project includes a desktop GUI and a CLI, runs on Windows, Linux, and macOS, and does not require Nmap for core scanning.

Intended for authorized network diagnostics, DNS verification, internal network checks, and security testing on systems you own or are explicitly permitted to assess.

Developed by PradaFit.

<img width="1280" height="720" alt="NetRecon_Images/NetRecon_Img_2.png" src="https://github.com/PradaFit/NetRecon/blob/main/NetRecon_Images/NetRecon_Img_2.png?raw=true" />

## Available on Microsoft Store

**NetRecon Network Toolkit** is the official Microsoft Store edition of NetRecon, published by PradaFitDev.

- Store listing: https://apps.microsoft.com/store/detail/9N0FM1DQSB34?cid=DevShareMCLPCS
- One-click install on Windows 10 (1809+) and Windows 11, x64
- Automatic updates through the Microsoft Store
- Available through the Microsoft Store as a full-trust packaged desktop app

The GitHub releases page continues to host the standalone Inno Setup installer (`NetRecon-Setup-*.exe`) and the source distribution for users who prefer manual install, portable use, or building from source. Both editions share the same engine, feature set, and local-first design.

| Edition | Distribution | Updates | Best for |
| --- | --- | --- | --- |
| Microsoft Store | MSIX package | Automatic via Store | Most Windows users |
| GitHub release | Inno Setup `.exe` | Manual download | Offline / portable / custom installs |
| Source | `git clone` + `pip` | `git pull` | Linux, macOS, dev work |

## Why NetRecon

Most small recon tools do one thing well and everything else as an afterthought. NetRecon is meant to be the daily-driver version: quick to launch, practical to use, and flexible enough to move between a GUI workflow and terminal-based checks without changing tools.

The biggest difference is the built-in native scanner. If Nmap is installed, NetRecon can use it. If it is not, the app still works with its own async TCP engine.

## Core Features

- Native async TCP scanner with high concurrency, non-blocking DNS resolution, and no external scanner requirement
- Optional Nmap integration for users who want classic service and OS detection workflows
- DNS toolkit with support for `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `PTR`, `SRV`, and `CAA`
- DNS propagation checks across public resolvers
- Reverse DNS and WHOIS lookups
- IP geolocation with provider failover
- Desktop GUI built with `customtkinter`
- CLI mode for fast terminal-driven recon
- Scan history stored in SQLite with safe connection lifecycle and `VACUUM` cleanup
- Export output to JSON, CSV, styled HTML, and interactive map/report formats where applicable
- Hardened input validation, sandboxed export paths, and parameterized database queries
- Cross-platform operation on Windows, Linux, and macOS
- Windows installer (Inno Setup) for Windows 10 / 11

## Interface Overview

NetRecon includes both of the workflows most people actually use:

- GUI for point-and-click scanning, DNS lookups, geo lookups, exports, and history review
- CLI for quick checks, scripting, and low-friction terminal work

The GUI includes dedicated tabs for:

- DNS Lookup
- Port Scanner
- Geolocation
- History

A built-in **About** window (top-right corner of the main window) exposes the project links, the responsible-use notice, the licence, and a one-click **Export Diagnostic Log** action that produces a sanitized text file for bug reports.

On first launch the GUI shows a short **Responsible Use** notice that must be accepted before the app continues. Acceptance is stored locally and is requested again only after a future major-version change.

## Native Scanner and Nmap Support

NetRecon supports two scanning paths.

### Native Scanner

The built-in scanner is the default path and is designed for fast, single-host checks. It uses a bounded async TCP worker pool, supports IPv4, IPv6, hostnames, and custom port selections, and remains available when Nmap is missing. CIDR ranges use an Nmap profile.

Default configuration:

- `native_quick` profile by default
- The active **Native Scan Speed** selector has four tiers: **Safe (500)**, **Balanced (1500)**, **Fast (4000)** (default), and **Extreme (8000)**. The Extreme tier requires explicit confirmation.
- `1.5s` connect timeout
- Bounded task creation instead of allocating one async task per port
- Immediate cancellation of active probes and banner reads

### Nmap Integration

If Nmap is installed and available in `PATH`, NetRecon can switch to Nmap-backed profiles for users who want deeper service detection or traditional Nmap output behavior.

If Nmap is not installed, NetRecon still remains fully usable for its core scanning workflow.

Nmap profiles are launched as a directly managed local process. The Cancel button terminates that process immediately. When an Nmap profile is active, the UI displays **Nmap Scan Speed** instead of the native concurrency selector. It defaults to the profile's timing and can be explicitly overridden. Switching back to a native profile restores the enabled native speed selector.

Nmap status records are streamed into the live progress bar with the current phase, percentage when Nmap provides one, and elapsed time. Built-in scans use a 30-minute per-host ceiling and a 5-minute per-script ceiling. The explicitly labeled extended profiles use 60-minute host and 15-minute script ceilings. Custom authorized commands can select different limits. If a Ports value is supplied, it overrides profile-wide choices such as `-F`, `--top-ports`, or `-p-`.

| Profile | Intended behavior |
|---|---|
| Quick Scan | Nmap's most common 100 TCP ports |
| Default Scan | Default TCP ports with service detection |
| Intense Scan | All TCP ports with service, OS, script, and route detection |
| SYN Scan | TCP SYN scan with conservative timing |
| UDP Scan | Nmap's 100 most common UDP ports |
| Vulnerability Checks | Service detection plus safe, target-scoped vulnerability scripts |
| Extended Vulnerability Checks | Full `vuln` category for explicitly authorized work orders; confirmation required in the GUI |
| Ping Sweep | Host discovery only |
| OS Detection | Operating-system fingerprinting |
| Service Version | Detailed service/version detection |
| Comprehensive | All TCP ports with detection and safe, target-scoped scripts |
| Extended Comprehensive | All TCP ports plus full default and `vuln` categories; confirmation required in the GUI |
| Native Quick | Top 1000 TCP ports on one host |
| Native Full Range | All 65535 TCP ports on one host |
| Native Custom | User-selected TCP ports on one host |

## DNS Toolkit

NetRecon is not limited to basic record lookups. The DNS engine includes:

- single-record lookups
- all-record sweeps across supported record types
- reverse lookups
- propagation checks across public DNS servers
- WHOIS queries
- zone transfer attempts for authorized testing scenarios

This makes it useful for routine DNS troubleshooting, domain recon, and quick verification work after record changes.

## Geolocation

The geo engine can resolve public IP metadata including location, ISP, ASN, and reverse DNS details when available. It uses HTTPS-only providers with failover behavior. Private, loopback, reserved, and other non-public addresses are rejected before a provider request.

## Export and History

Results can be kept, reviewed, and moved into reports without extra cleanup work.

- SQLite-backed history store
- JSON export
- CSV export
- styled HTML export
- interactive report or map output where the result type supports it

This is useful if you want one tool for both collection and handoff.

## Quick Start

### Option A: Windows Installer

Download the latest `NetRecon-Setup-*.exe` from the Releases page (or install from the Microsoft Store) and run it. The installer supports Windows 10 (1809+) and Windows 11 on x64, creates Start Menu and optional desktop shortcuts, and preserves user data under `%USERPROFILE%\.netrecon` across upgrades and uninstalls.

### Option B: From Source

#### 1. Clone the repository

```bash
git clone https://github.com/PradaFit/NetRecon.git
cd NetRecon
```

#### 2. Install dependencies

```bash
pip install -r requirements.txt
```

#### 3. Launch the GUI

```bash
python main.py
```

#### 4. Launch the CLI

```bash
python main.py --cli
```

## CLI Examples

### DNS lookup

```bash
python main.py dns example.com
python main.py dns example.com --type MX
```

### Native port scan

```bash
python main.py scan 192.168.1.1
python main.py scan 192.168.1.1 --profile native_custom --ports 22,80,443
```

### Nmap-backed scan

```bash
python main.py scan 192.168.1.1 --nmap
python main.py scan 192.168.1.0/24 --profile quick --nmap
```

### IP geolocation

```bash
python main.py geo 8.8.8.8
python main.py geo --myip
```

## Installation Notes

- Python dependencies are listed in `requirements.txt`
- Nmap is optional, not required
- The project was developed and tested around Python `3.12`
- GUI support depends on `customtkinter` and `Pillow`

## Security Notes

NetRecon includes input validation and defensive handling in the core engines.

- target and port input validation for IPv4, IPv6, CIDR, and hostnames; native profiles intentionally accept one host while Nmap profiles accept CIDR
- a strict custom Nmap option allowlist; file inputs/outputs, proxies, external data files, resume, arbitrary NSE paths, and script arguments are rejected
- safe built-in vulnerability profiles exclude scripts tagged external or broadcast; full-category extended profiles remain available behind an explicit scope warning for authorized work orders
- bounded Nmap host/script execution with live phase and timing updates
- export paths sandboxed to home, temp, and working directory roots using real-path containment checks
- SQLite connections wrapped with `contextlib.closing` and parameterized queries throughout
- HTML escaping in report generation
- coordinate coercion on geo map output to prevent injection into rendered Folium popups

This does not make reckless scanning safe. It means the application is not casually trusting user input.

## Project Layout

```text
.
|-- main.py
|-- config.json
|-- requirements.txt
|-- gui/
|-- netrecon/
|-- DISCLAIMER.md
|-- LICENSE
```

## Practical Use Cases

- DNS troubleshooting and propagation verification
- internal host inventory on networks you administer
- service exposure checks before publishing a host
- public IP and ASN lookups
- lightweight reporting and export for follow-up work
- authorized security testing engagements

## Privacy

NetRecon does not include telemetry, analytics, or third-party trackers. Scan results, history, preferences, and diagnostic logs are stored locally under `%USERPROFILE%\.netrecon` on Windows or `~/.netrecon` elsewhere. Geolocation lookups and traceroute-hop geolocation send public IP addresses to the documented HTTPS providers only when you run those features. Interactive maps load OpenStreetMap tiles when opened.

## Legal and Responsible Use

Use NetRecon only on systems, networks, and domains you own or are explicitly authorized to assess.

Review the project disclaimer in `DISCLAIMER.md` before use. The repository is licensed under GPLv3.

## Keywords

Python port scanner, Nmap GUI, DNS lookup tool, network reconnaissance toolkit, async TCP scanner, WHOIS lookup, IP geolocation, cross-platform network scanner, Python network tools.
