# NetRecon Privacy Policy

**App:** NetRecon
**Version:** 2.0.0
**Publisher:** PradaFitDev
**License:** GNU General Public License v3.0 (open source)
**Effective date:** 2026-05-17

NetRecon is an open-source desktop and command-line toolkit for DNS
lookups, port scanning, IP geolocation, and related network
diagnostics. This document explains exactly what data the application
handles, where it goes, and what it never does.

---

## 1. Summary

- No telemetry
- No analytics
- No advertising
- No third-party tracking SDKs
- No user accounts
- No data is sold, rented, or shared with marketing partners
- No data is transmitted in the background

NetRecon does not collect personal information about you. It does not
phone home. It does not run any code on launch other than what is
needed to render the local user interface.

---

## 2. Data stored locally on your device

NetRecon stores the following data under your user profile, inside the
NetRecon application data folder (on Windows this resolves to
`%USERPROFILE%\.netrecon`):

- **Preferences** (`preferences.json`)
  Small JSON file recording the responsible-use acceptance flag and UI
  settings.
- **Scan history** (`history.db`)
  Local SQLite database containing the targets you scanned, the
  results, and timestamps. This file never leaves your device unless
  you choose to export it.
- **Diagnostic logs** (`logs/netrecon.log` and rotated copies)
  Rolling log file used for in-app troubleshooting. Log lines are
  sanitized at write time: home directory paths, IP addresses, and
  email addresses are redacted before being written to disk.

All of these files are owned by your Windows user account. Uninstalling
NetRecon does not delete them. You can remove them at any time by
deleting the `%USERPROFILE%\.netrecon` folder.

---

## 3. Data you can voluntarily export

You can choose to export the following to a location of your choice:

- Scan results (JSON, CSV, HTML, or interactive map)
- Diagnostic log (sanitized text file, produced from the **About >
  Diagnostics** tab)

Exports only happen when you explicitly trigger them. NetRecon never
uploads any of these files anywhere.

---

## 4. Network features that contact third parties

Some features, by design, must talk to the network. NetRecon only
contacts third-party services **when you run that specific feature**
and **only for the target you provided**.

| Feature | What is sent | Where it goes |
|---|---|---|
| DNS Lookup | The domain or IP you typed | Your system's DNS resolver, plus optional public resolvers if you enable propagation checks |
| Reverse DNS | The IP you typed | Your system's DNS resolver |
| WHOIS | The domain you typed | Public WHOIS servers |
| IP Geolocation | The IP you typed | Public IP geolocation APIs (multiple providers, with failover) |
| Port Scan (native) | TCP connect attempts | The target host you specified |
| Port Scan (Nmap) | Standard Nmap probes | The target host you specified |

NetRecon does not send your IP, identity, license key, machine ID, or
any usage statistics to these services. It only sends the network
query needed to satisfy the request you made.

These third-party services have their own privacy policies. NetRecon
is not affiliated with them.

---

## 5. Nmap

Nmap is an **optional** dependency. NetRecon does not bundle or install
Nmap. If you choose to install Nmap and enable the Nmap path, NetRecon
will invoke the local `nmap` executable on your machine with a
validated argument allowlist. Nmap is governed by its own license and
project policies.

---

## 6. Responsible use

NetRecon is intended for use only on systems, networks, and domains
that you own or are explicitly authorized to assess. You are
responsible for complying with the laws of your jurisdiction and any
applicable terms of service.

A short responsible-use notice is shown the first time the application
launches. Continuing past that notice records your acceptance locally
in `preferences.json`.

---

## 7. Children

NetRecon is a network diagnostics tool intended for IT professionals,
developers, and system administrators. It is not directed at children
and does not knowingly collect data from anyone.

---

## 8. Security

Because NetRecon stores no remote data, there is no remote breach
surface tied to your usage. Local files (`preferences.json`,
`history.db`, log files) are protected by the standard Windows file
permissions of your user account. Source code is published openly so
that this claim is auditable.

---

## 9. Changes to this policy

Material changes to this policy will be reflected here in the
repository and in the version of the file bundled with each installer.
The "Effective date" at the top of the document indicates the last
revision.

---

## 10. Contact

Support and privacy questions:
**GitHub Issues:** https://github.com/PradaFit/NetRecon/issues

For source-level review, see the public repository:
**Repository:** https://github.com/PradaFit/NetRecon
