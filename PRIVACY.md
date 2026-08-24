# NetRecon Privacy Policy

**App:** NetRecon
**Version:** 2.0.5
**Publisher:** PradaFitDev
**License:** GNU General Public License v3.0 (open source)
**Effective date:** 2026-08-24

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
phone home. On launch it renders the interface and initializes its local
preferences, log, and history storage. It makes no network request until
you trigger a network feature.

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
| IP Geolocation | The public IP you typed or the public IP resolved from a domain | `ipwho.is` or `ipapi.co`, over HTTPS, with failover |
| My Public IP | Your request's source IP, as visible to any internet service | `api.ipify.org`, `ifconfig.me`, or `icanhazip.com`, over HTTPS |
| Traceroute Map | Standard traceroute probes, then each public hop IP | The target path and the HTTPS geolocation providers above |
| Port Scan (native) | TCP connect attempts | The target host you specified |
| Port Scan (Nmap standard profiles) | Standard Nmap probes; safe vulnerability profiles exclude external and broadcast scripts | The target host you specified |
| Port Scan (Nmap extended profiles) | Full Nmap script-category traffic; depending on installed Nmap scripts, this can include local discovery or service metadata | The target, other systems discovered by an eligible broadcast script, or an external service used by an eligible script |
| Interactive Map | Map tile requests, which reveal the viewer's source IP and visible map area | OpenStreetMap tile servers when you open the generated HTML map |

NetRecon does not send an account identity, license key, machine ID, or
usage statistics to these services. As with any internet request, a
third-party service can observe the request's source IP. NetRecon sends
only the query needed to satisfy the feature you selected. Private,
loopback, reserved, and other non-public addresses are not sent to the
geolocation providers.

These third-party services have their own privacy policies. NetRecon
is not affiliated with them.

---

## 5. Nmap

Nmap is an **optional** dependency. NetRecon does not bundle or install
Nmap. If you choose to install Nmap, NetRecon invokes the local `nmap`
executable without a command shell. Built-in profiles use fixed arguments,
and custom arguments pass a strict option allowlist that rejects file I/O,
proxies, external data files, arbitrary NSE paths, and script arguments.
The standard Vulnerability Checks and Comprehensive profiles filter their
NSE selection to scripts tagged safe and exclude scripts tagged external or
broadcast. Extended Vulnerability Checks and Extended Comprehensive preserve
the full Nmap `vuln` category for explicitly authorized work orders. The GUI
shows a detailed confirmation before either extended profile runs. The exact
behavior of an extended profile depends on the scripts installed with the
user's local Nmap version and can include intrusive, exploit, denial-of-service,
broadcast, or external-provider behavior.
Nmap is governed by its own license and project policies.

---

## 6. Responsible use

NetRecon is intended for use only on systems, networks, and domains
that you own or are explicitly authorized to assess. You are
responsible for complying with the laws of your jurisdiction and any
applicable terms of service.

A short responsible-use notice is shown the first time the application
launches and again after a future major-version change. Continuing past
that notice records your acceptance locally in `preferences.json`.

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
