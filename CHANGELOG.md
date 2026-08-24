# NetRecon Changelog

## 2.0.4 - 2026-08-23

### Fixed

- Reworked the scan speed area so Nmap profiles show an enabled Nmap timing selector and native profiles show an enabled native concurrency selector after every profile transition.
- Made programmatic dropdown changes invoke their state callback, preventing dependent controls from retaining stale enabled or disabled states.
- Replaced the animated-only scan indicator with streamed Nmap phase/percentage updates and an always-live elapsed timer.

### Security and field operation

- Restricted standard Vulnerability Checks and Comprehensive profiles to safe, target-scoped NSE selections that exclude external and broadcast scripts.
- Preserved the full Nmap `vuln` category in explicitly labeled extended profiles for authorized work orders and added a detailed GUI confirmation before execution.
- Added default Nmap host and script ceilings while allowing explicit custom timeout overrides.
- Updated the privacy disclosure for extended scripts that can discover other local systems or contact external providers.

### Verification

- Added regression coverage for every Nmap/native speed-control transition, programmatic dropdown changes, progress rendering, timeout injection, and extended-profile confirmation.
- Synchronized application, executable, installer, development manifest, and Microsoft Store package inputs at version 2.0.4 / 2.0.4.0.

## 2.0.3 - 2026-08-23

### Fixed

- Cancel now interrupts active native probe/banner tasks and terminates the live Nmap process instead of waiting for scan completion.
- Corrected Nmap timing overrides, preserved profile identity, and made explicit port selections override `-F`, `--top-ports`, and `-p-` profile defaults.
- Verified every native and Nmap scan profile against controlled localhost targets.
- Fixed reverse DNS resolver initialization.
- Fixed UI worker-to-Tk communication with a main-thread event queue, preventing stuck controls and shutdown errors.
- Added accurate success, warning, cancellation, and failure states across DNS, scan, and geolocation actions.
- Fixed complete history export, mixed-column CSV export, spreadsheet formula neutralization, zero-coordinate maps, and raw coordinate handling.
- Fixed native IPv6 connections and added an actionable single-host message for native CIDR input.
- Fixed packaged builds so bundled configuration is loaded from the PyInstaller runtime directory.

### Performance

- Replaced per-port async task allocation with a bounded worker pool.
- Updated the default native speed tier to Fast (4000 workers) while retaining Safe, Balanced, and opt-in Extreme tiers.
- Reduced banner wait time and avoided Nmap reverse-DNS delays in built-in profiles.
- Added an exact, unique 1000-port native quick set based on Nmap service-frequency data.

### Security and packaging

- Replaced the plaintext geolocation endpoint with HTTPS-only providers and added response-size, HTTP-status, coordinate, and public-IP validation.
- Replaced permissive Nmap character filtering with a strict custom-option allowlist and shell-free process execution.
- Hardened Nmap XML parsing with `defusedxml`.
- Removed the hardcoded development certificate password from the MSIX workflow and select the dedicated development manifest for sideload signing.
- Pinned direct runtime and build/test dependencies, added the missing `python-whois` dependency, and removed the obsolete `python-nmap` runtime dependency.
- Synchronized application, executable, installer, development manifest, and Microsoft Store package inputs at version 2.0.3 / 2.0.3.0.

### Privacy and documentation

- Documented public-IP detection, traceroute-hop geolocation, OpenStreetMap tile requests, full-trust MSIX capabilities, native single-host scope, and profile behavior.
