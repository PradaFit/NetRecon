# NetRecon

NetRecon is a Python network reconnaissance toolkit built for fast DNS lookups, async TCP port scanning, optional Nmap-driven enumeration, IP geolocation, and exportable scan history. It ships with a desktop GUI and a CLI, runs on Windows, Linux, and macOS, and does not require Nmap for core scanning.

Developed by PradaFit.

## Why NetRecon

Most small recon tools do one thing well and everything else as an afterthought. NetRecon is meant to be the daily-driver version: quick to launch, practical to use, and flexible enough to move between a GUI workflow and terminal-based checks without changing tools.

The biggest difference is the built-in native scanner. If Nmap is installed, NetRecon can use it. If it is not, the app still works with its own async TCP engine.

## Core Features

- Native async TCP scanner with high concurrency and no external scanner requirement
- Optional Nmap integration for users who want classic service and OS detection workflows
- DNS toolkit with support for `A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`, `CNAME`, `PTR`, `SRV`, and `CAA`
- DNS propagation checks across public resolvers
- Reverse DNS and WHOIS lookups
- IP geolocation with provider failover
- Desktop GUI built with `customtkinter`
- CLI mode for fast terminal-driven recon
- Scan history stored in SQLite with export support
- Export output to JSON, CSV, styled HTML, and interactive map/report formats where applicable
- Cross-platform operation on Windows, Linux, and macOS

## Interface Overview

NetRecon includes both of the workflows most people actually use:

- GUI for point-and-click scanning, DNS lookups, geo lookups, exports, and history review
- CLI for quick checks, scripting, and low-friction terminal work

The GUI includes dedicated tabs for:

- Scan
- DNS
- Geo
- History

## Native Scanner and Nmap Support

NetRecon supports two scanning paths.

### Native Scanner

The built-in scanner is the default path and is designed for speed. It uses async TCP connections, supports custom port selections, and avoids the common problem of a GUI tool becoming unusable on machines where Nmap is missing.

Default configuration includes:

- `native_quick` profile by default
- `8000` configured native concurrency
- `1.5s` native timeout
- configurable memory cap safeguards

### Nmap Integration

If Nmap is installed and available in `PATH`, NetRecon can switch to Nmap-backed profiles for users who want deeper service detection or traditional Nmap output behavior.

If Nmap is not installed, NetRecon still remains fully usable for its core scanning workflow.

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

The geo engine can resolve public IP metadata including location, ISP, ASN, and reverse DNS details when available. It uses multiple providers with failover behavior instead of relying on a single endpoint.

## Export and History

Results can be kept, reviewed, and moved into reports without extra cleanup work.

- SQLite-backed history store
- JSON export
- CSV export
- styled HTML export
- interactive report or map output where the result type supports it

This is useful if you want one tool for both collection and handoff.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/PradaFit/NetRecon.git
cd NetRecon
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Launch the GUI

```bash
python main.py
```

### 4. Launch the CLI

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
python main.py scan 192.168.1.0/24 -p quick
```

### Nmap-backed scan

```bash
python main.py scan 192.168.1.1 --nmap
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

- target and port input sanitization
- blocked dangerous shell-style input patterns
- restricted export paths
- parameterized SQLite queries
- HTML escaping in report generation

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

- DNS troubleshooting
- fast internal host checks
- service exposure verification
- external IP lookups
- simple recon workflows from a single desktop app
- lightweight reporting and export for follow-up work

## Legal and Responsible Use

Use NetRecon only on systems, networks, and domains you own or are explicitly authorized to assess.

Review the project disclaimer in `DISCLAIMER.md` before use. The repository is licensed under GPLv3.

## Keywords

Python port scanner, Nmap GUI, DNS lookup tool, network reconnaissance toolkit, async TCP scanner, WHOIS lookup, IP geolocation, cross-platform network scanner, Python network tools.
