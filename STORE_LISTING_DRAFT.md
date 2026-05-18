# NetRecon: Microsoft Store Listing Draft

This document captures the public-facing metadata for the Microsoft Store
submission. Treat it as the source of truth; the Partner Center fields
should match what is written here.

## App name

NetRecon

## Publisher

PradaFitDev

## Short description (max 200 chars)

Professional network diagnostics toolkit for DNS lookups, port scanning,
and IP geolocation. Built for IT admins, developers, and authorized
security testing.

## Full description

NetRecon is a desktop and command-line toolkit for network diagnostics,
DNS verification, internal network checks, and authorized security
testing.

It ships with a native async TCP scanner, a full DNS toolkit, IP
geolocation, exportable scan history, and an optional integration with
Nmap when it is installed. Nothing requires elevated privileges for the
default workflow.

NetRecon is intended for use on systems, networks, and domains that you
own or are explicitly authorized to assess. It is not a hacking tool and
does not perform exploitation or evasion.

### Highlights

- Native async TCP port scanner that works without Nmap
- Optional Nmap integration for service and OS detection
- DNS toolkit: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA
- DNS propagation checks across public resolvers
- Reverse DNS and WHOIS lookups
- IP geolocation with provider failover
- Desktop GUI and CLI in a single install
- Scan history stored locally in SQLite
- Export to JSON, CSV, styled HTML, and interactive map reports
- Hardened input validation and sandboxed export paths
- No telemetry, no analytics, no tracking

### Responsible use

NetRecon must only be used on networks and systems that you own or are
explicitly authorized to assess. Users accept a responsible-use notice
on first launch.

## Feature bullets (Store)

- Native async TCP scanner, no external dependency required
- Optional Nmap integration when installed
- Full DNS record toolkit, propagation, WHOIS, reverse lookup
- IP geolocation with provider failover
- Local SQLite scan history with export
- JSON, CSV, HTML, and interactive map exports
- No telemetry. Scan results, history, preferences, and logs stay on your machine. Geolocation lookups contact public IP lookup APIs only when you trigger them.

## Keywords

network diagnostics, DNS lookup, port scanner, IP geolocation, WHOIS,
network troubleshooting, network admin tools, async TCP scanner,
authorized security testing, IT toolkit

## Suggested category

Developer Tools (primary), Utilities & Tools (secondary)

## Age rating

12+ (utility software, no objectionable content)

## Price

Free

## Privacy policy URL

https://github.com/PradaFit/NetRecon/blob/main/PRIVACY.md

## Support URL

https://github.com/PradaFit/NetRecon/issues

## Website URL

https://github.com/PradaFit/NetRecon

## Monetization

No paid features. No advertising. No in-app purchases. The About window
contains an optional "Support Development" button that opens an external
link in the user's browser. This is a voluntary tip jar, never required
to use any feature.

## Privacy

- No telemetry
- No analytics
- No third-party tracking SDKs
- Scan results, history, preferences, and logs are stored locally under
  `%USERPROFILE%\.netrecon`
- IP geolocation queries are sent to public lookup APIs only when the
  user runs a geolocation lookup, and only contain the IP supplied by
  the user

## System requirements

- Windows 10 version 1809 or newer
- Windows 11
- x64 and ARM64 (ARM64 via Windows on ARM emulation when needed)

## Required capabilities

- internetClient (DNS and geolocation lookups)

## Suggested screenshots

1. DNS Lookup tab with results for a sample domain
2. Port Scanner tab showing a native quick scan of a local subnet
3. Geolocation tab with a public IP result on the map
4. History tab listing previous scans
5. About window with project links and the Responsible Use tab open

## Support contact

GitHub Issues: https://github.com/PradaFit/NetRecon/issues
