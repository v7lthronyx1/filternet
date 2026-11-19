# Cross-Platform Setup Guide (Windows, macOS, Linux)

`filternet` runs on Python 3.9+ using only the standard library. No third-party `pip` packages are required for `doctor`, `probe`, `hosts-pin`, `wg-prepare`, or `dns-config`.

---

## Install or Run Directly

Run straight from a cloned checkout:
```bash
git clone https://github.com/v7lthronyx1/filternet.git
cd filternet
python -m filternet doctor
```

Or install the `filternet` command (`pip install .` on Windows/macOS, or `pipx install .` on Debian/Ubuntu/Kali Linux):
```bash
pipx install .
filternet doctor
```

---

## 1. Windows

### Run Diagnostics & Filtering Probes
```powershell
python -m filternet doctor
python -m filternet probe
```
To test a specific adapter IP:
```powershell
python -m filternet probe -i 192.168.1.50
```

### Encrypted DNS (Bare-IP DoH via `dnscrypt-proxy`)
Plain UDP/TCP `53`, non-standard `5353`, `DoT (853/tcp)`, `DoQ (853/udp)`, and domain-SNI `DoH` are intercepted on filtered networks. Use bare-IP DoH stamps instead:
1. Download the official Windows build of `dnscrypt-proxy`.
2. Generate the Windows config (`listen_addresses = ['127.0.0.1:53']`):
   ```powershell
   filternet dns-config --target crossplatform -o dnscrypt-proxy.toml
   ```
3. Install and start the Windows service from an elevated PowerShell prompt:
   ```powershell
   .\dnscrypt-proxy.exe -service install
   .\dnscrypt-proxy.exe -service start
   ```
4. Set your active adapter DNSv4 server to `127.0.0.1`.

### WireGuard Optimization (`MTU = 1280`)
Before importing any `.conf` into the official WireGuard Windows client:
```powershell
filternet wg-prepare .\raw-profile.conf -o .\clean-profile.conf
```
This removes conflicting `DNS =` overrides, pins `MTU = 1280`, adds `PersistentKeepalive = 25`, and resolves domain endpoints over bare-IP DoH (`1.1.1.1`) so poisoned local DNS never stalls the handshake.

### Pin Healthy Fastly POPs (GitHub Releases / Debian Containers / PyPI)
Run from an **Administrator** PowerShell prompt:
```powershell
python -m filternet hosts-pin status
python -m filternet hosts-pin apply
```
To undo later:
```powershell
python -m filternet hosts-pin revert
```

### Windscribe Desktop Settings on Filtered Mobile Connections
- Leave **Custom SNI** either blank or as a bare hostname (`github.com`), never a full URL (`https://github.com/`).
- Turn off **Protocol Tweaks** if `WStunnel`/`Stealth` logs `packet was truncated/expanded` or WireGuard drops handshakes.
- Turn off **MAC Spoofing (Auto-rotate)** if switching between Wi-Fi and USB tethering stalls for 30+ seconds.
- On tethered mobile links (`MCI`), test European regions (`Frankfurt`, `Amsterdam`) if US locations blackhole after connecting.

---

## 2. macOS

### Run Diagnostics & Filtering Probes
```bash
python3 -m filternet doctor
python3 -m filternet probe
```

### Encrypted DNS (`dnscrypt-proxy` via Homebrew)
```bash
brew install dnscrypt-proxy
filternet dns-config --target crossplatform -o "$(brew --prefix)/etc/dnscrypt-proxy.toml"
sudo brew services start dnscrypt-proxy
```
Then point macOS Wi-Fi / Ethernet DNS to `127.0.0.1`:
```bash
networksetup -setdnsservers Wi-Fi 127.0.0.1
```

### WireGuard & Fastly Mirror Pinning
Prepare a `.conf` for the macOS WireGuard app (or `wireguard-tools` via Homebrew):
```bash
filternet wg-prepare ~/Downloads/profile.conf -o ~/Downloads/profile-clean.conf
```
Pin healthy Fastly POPs in `/etc/hosts`:
```bash
sudo python3 -m filternet hosts-pin apply
```

---

## 3. Linux

### Core Cross-Platform CLI
```bash
python3 -m filternet doctor
python3 -m filternet probe
sudo python3 -m filternet hosts-pin apply
filternet wg-prepare ~/Downloads/raw.conf -o ~/Downloads/clean.conf
```

### Linux-Specific System Cleanup & WireGuard Helpers
- **`configs/dnscrypt-proxy/dnscrypt-proxy.toml` + `resolved.conf`**: For `systemd-socket` setups listening on `127.0.2.1:53` with `DNSOverTLS=no` in `/etc/systemd/resolved.conf`.
- **`./scripts/diagnose-vpn.sh`**: Checks NetworkManager configs, leftover bridges (`172.20.0.0/16`), `ip rule` / `nft` leftovers, Surfshark `cache.json` poisoning, `PMTU`, `PortQuiz`, and Fastly mirrors.
- **`./scripts/ss-wg`**: Manages WireGuard tunnels (`fix-system`, `up`, `down`, `clean`, `status`), cleans leftover rules/tables, keeps `ss-*` unmanaged in NetworkManager (`90-ss-wg-unmanaged.conf`), and verifies both handshake and live HTTPS (`https://1.1.1.1`).
- **`./scripts/fix-fastly-apt.sh`**: Pins healthy Fastly POPs in `/etc/hosts` and installs `configs/apt/99-filternet-ipv4.conf` (`Acquire::ForceIPv4 "true";`) to `/etc/apt/apt.conf.d/99-filternet-ipv4`.
